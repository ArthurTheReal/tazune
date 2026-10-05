use crate::byte_buffer::BytePacketBuffer;
use crate::dns::{DnsHeader, DnsPacket, DnsQuestion, QueryType, ResultCode};
use crate::errors::TazuneError;

use log::{debug, error, info, warn};
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

fn check_id(expected: u16, received: u16) -> Result<(), TazuneError> {
    if expected != received {
        return Err(TazuneError::IdMismatch { expected, received });
    }

    Ok(())
}

fn random_id() -> u16 {
    RandomState::new().build_hasher().finish() as u16
}

fn query_tcp(server: SocketAddr, request: &[u8]) -> Result<BytePacketBuffer, TazuneError> {
    let mut stream = TcpStream::connect(server)?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;

    // DNS over TCP prefixes every message with its length as a big-endian u16.
    stream.write_all(&(request.len() as u16).to_be_bytes())?;
    stream.write_all(request)?;

    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes)?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    let mut buffer = BytePacketBuffer::new(len);
    stream.read_exact(buffer.buf_mut())?;

    Ok(buffer)
}

pub fn lookup(
    qname: String,
    qtype: QueryType,
    server: SocketAddr,
) -> Result<DnsPacket, TazuneError> {
    debug!("asking {server} for {qname} {qtype:?}");

    // The local socket has to be the same address family as the upstream.
    let bind_addr = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let mut packet = DnsPacket::new();

    packet.header.id = random_id();
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet.questions.push(DnsQuestion::new(qname, qtype));

    let mut req_buffer = BytePacketBuffer::new(512);
    packet.write(&mut req_buffer)?;

    socket.send_to(req_buffer.written(), server)?;

    let mut res_buffer = BytePacketBuffer::new(512);
    socket.recv_from(res_buffer.buf_mut())?;

    let header = DnsHeader::read(&mut res_buffer)?;
    check_id(packet.header.id, header.id)?;

    let res_packet = if header.truncated_message {
        info!("response from {server} was truncated, retrying over TCP");

        let mut tcp_buffer = query_tcp(server, req_buffer.written())?;
        let tcp_packet = DnsPacket::from_buffer(&mut tcp_buffer)?;
        check_id(packet.header.id, tcp_packet.header.id)?;

        tcp_packet
    } else {
        res_buffer.seek(0)?;
        DnsPacket::from_buffer(&mut res_buffer)?
    };

    debug!(
        "{server} replied {:?} with {} answers",
        res_packet.header.rescode,
        res_packet.answers.len()
    );

    Ok(res_packet)
}

// the set of upstream resolvers. Queries are spread across them round-robin, and
// if the chosen one fails the remaining ones are tried
// in order before giving up. Shared between worker threads through an Arc.
struct Upstreams {
    resolvers: Vec<SocketAddr>,
    next: AtomicUsize,
}

impl Upstreams {
    fn new(resolvers: Vec<SocketAddr>) -> Upstreams {
        Upstreams {
            resolvers,
            next: AtomicUsize::new(0),
        }
    }

    fn lookup(&self, qname: &str, qtype: QueryType) -> Result<DnsPacket, TazuneError> {
        let start = self.next.fetch_add(1, Ordering::Relaxed);

        let mut last_err = None;
        for i in 0..self.resolvers.len() {
            let server = self.resolvers[start.wrapping_add(i) % self.resolvers.len()];
            match lookup(qname.to_string(), qtype, server) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    warn!("upstream {server} failed for {qname}: {e}");
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or(TazuneError::NoUpstreams))
    }
}

fn serialize(response: &mut DnsPacket) -> Result<BytePacketBuffer, TazuneError> {
    let mut buffer = BytePacketBuffer::new(512);
    if response.write(&mut buffer).is_ok() {
        return Ok(buffer);
    }

    // Didn't fit in 512 bytes: empty reply with the TC bit, client retries over TCP.
    warn!("response too large for UDP, sending a truncated reply");
    response.answers.clear();
    response.header.truncated_message = true;
    let mut buffer = BytePacketBuffer::new(512);
    response.write(&mut buffer)?;

    Ok(buffer)
}

fn build_response(request: &DnsPacket, upstreams: &Upstreams) -> DnsPacket {
    let mut response = DnsPacket::new();
    response.header.id = request.header.id;
    response.header.response = true;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = true;
    response.questions = request.questions.clone();

    if request.questions.len() != 1 {
        warn!(
            "expected exactly one question, got {}",
            request.questions.len()
        );
        response.header.rescode = ResultCode::FORMERR;
        return response;
    }

    let question = &request.questions[0];
    match upstreams.lookup(&question.name, question.qtype) {
        Ok(upstream_response) => {
            response.header.rescode = upstream_response.header.rescode;
            response.answers = upstream_response.answers;
        }
        Err(e) => {
            warn!("lookup of {} failed on every upstream: {e}", question.name);
            response.header.rescode = ResultCode::SERVFAIL;
        }
    }

    response
}

// Everything that happens after a request was received and parsed. This is the
// slow part (it waits on the upstream resolvers), so it runs on a worker thread.
fn handle_request(
    socket: &UdpSocket,
    request: &DnsPacket,
    src: SocketAddr,
    upstreams: &Upstreams,
    started: Instant,
) {
    let question = request
        .questions
        .first()
        .map(|q| format!("{} {:?}", q.name, q.qtype))
        .unwrap_or_else(|| "<no question>".to_string());
    debug!("query from {src}: {question}");

    let mut response = build_response(request, upstreams);
    let buffer = match serialize(&mut response) {
        Ok(b) => b,
        Err(e) => {
            error!("couldn't serialize response for {src}: {e}");
            return;
        }
    };

    if let Err(e) = socket.send_to(buffer.written(), src) {
        warn!("send to {src} failed: {e}");
        return;
    }

    let rescode = response.header.rescode;
    let answers = response.answers.len();
    let elapsed = started.elapsed();
    info!("{src} {question} -> {rescode:?}, {answers} answers, {elapsed:?}");
}

pub fn proxy_server(
    upstream_resolvers: Vec<SocketAddr>,
    listen_addr: SocketAddr,
) -> Result<(), TazuneError> {
    if upstream_resolvers.is_empty() {
        return Err(TazuneError::NoUpstreams);
    }

    // Arc lets the main loop and every worker share one socket. recv_from and
    // send_to both take &self, so no lock is needed.
    let socket = Arc::new(UdpSocket::bind(listen_addr)?);
    let upstreams = Arc::new(Upstreams::new(upstream_resolvers));

    info!(
        "listening on {listen_addr}, forwarding to {} upstream resolvers: {:?}",
        upstreams.resolvers.len(),
        upstreams.resolvers
    );

    loop {
        let mut user_request_buffer = BytePacketBuffer::new(512);
        let (_, src) = match socket.recv_from(user_request_buffer.buf_mut()) {
            Ok(x) => x,
            Err(e) => {
                error!("recv failed: {e}");
                continue;
            }
        };
        let started = Instant::now();

        let user_request_packet = match DnsPacket::from_buffer(&mut user_request_buffer) {
            Ok(p) => p,
            Err(e) => {
                warn!("bad packet from {src}: {e}");
                continue;
            }
        };

        let worker_socket = Arc::clone(&socket);
        let worker_upstreams = Arc::clone(&upstreams);
        let spawned = thread::Builder::new()
            .name("worker".to_string())
            .spawn(move || {
                handle_request(
                    &worker_socket,
                    &user_request_packet,
                    src,
                    &worker_upstreams,
                    started,
                );
            });

        // Unlike thread::spawn, Builder::spawn returns an error instead of
        // panicking when the OS refuses to create a thread.
        if let Err(e) = spawned {
            error!("couldn't spawn a worker for {src}: {e}");
        }
    }
}
