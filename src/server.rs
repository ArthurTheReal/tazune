use crate::byte_buffer::BytePacketBuffer;
use crate::dns::{DnsHeader, DnsPacket, DnsQuestion, ResultCode, QueryType};
use crate::errors::TazuneError;

use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::Duration;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};

type Addr <'a> = (&'a str, u16);

fn check_id(expected: u16, received: u16) -> Result<(), TazuneError> {
    if expected != received {
        return Err(TazuneError::IdMismatch { expected, received });
    }

    Ok(())
}

fn random_id() -> u16 {
    RandomState::new().build_hasher().finish() as u16
}

fn query_tcp(server: (&str, u16), request: &[u8]) -> Result<BytePacketBuffer, TazuneError> {
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

pub fn lookup(qname: String, qtype: QueryType, server: Addr) -> Result<DnsPacket, TazuneError> {
    let socket = UdpSocket::bind(("0.0.0.0", 0))?;
    socket.set_read_timeout(Some(Duration::from_secs(3)))?;

    let mut packet = DnsPacket::new();

    packet.header.id = random_id();
    packet.header.questions = 1;
    packet.header.recursion_desired = true;
    packet
        .questions
        .push(DnsQuestion::new(qname, qtype));

    let mut req_buffer = BytePacketBuffer::new(512);
    packet.write(&mut req_buffer)?;

    socket.send_to(req_buffer.written(), server)?;

    let mut res_buffer = BytePacketBuffer::new(512);
    socket.recv_from(res_buffer.buf_mut())?;

    let header = DnsHeader::read(&mut res_buffer)?;
    check_id(packet.header.id, header.id)?;

    let res_packet = if header.truncated_message {
        println!("response was truncated, retrying over TCP");

        let mut tcp_buffer = query_tcp(server, req_buffer.written())?;
        let tcp_packet = DnsPacket::from_buffer(&mut tcp_buffer)?;
        check_id(packet.header.id, tcp_packet.header.id)?;

        tcp_packet
    } else {
        res_buffer.seek(0)?;
        DnsPacket::from_buffer(&mut res_buffer)?
    };

    Ok(res_packet)

}

fn serialize(response: &mut DnsPacket) -> Result<BytePacketBuffer, TazuneError> {
    let mut buffer = BytePacketBuffer::new(512);
    if response.write(&mut buffer).is_ok() {
        return Ok(buffer);
    }

    // Didn't fit in 512 bytes: empty reply with the TC bit, client retries over TCP.
    response.answers.clear();
    response.header.truncated_message = true;
    let mut buffer = BytePacketBuffer::new(512);
    response.write(&mut buffer)?;

    Ok(buffer)
}

fn build_response(request: &DnsPacket, upstream_resolver: Addr) -> DnsPacket {
    let mut response = DnsPacket::new();
    response.header.id = request.header.id;
    response.header.response = true;
    response.header.recursion_desired = request.header.recursion_desired;
    response.header.recursion_available = true;
    response.questions = request.questions.clone();

    if request.questions.len() != 1 {
        response.header.rescode = ResultCode::FORMERR;
        return response;
    }

    let question = &request.questions[0];
    match lookup(question.name.clone(), question.qtype, upstream_resolver) {
        Ok(upstream_response) => {
            response.header.rescode = upstream_response.header.rescode;
            response.answers = upstream_response.answers;
        }
        Err(e) => {
            eprintln!("lookup of {} failed: {e}", question.name);
            response.header.rescode = ResultCode::SERVFAIL;
        }
    }

    response
}

pub fn proxy_server(upstream_resolver: Addr, listen_addr: Addr) -> Result<(), TazuneError> {
    let socket = UdpSocket::bind(listen_addr)?;

    loop {
        let mut user_request_buffer = BytePacketBuffer::new(512);
        let (_, src) = match socket.recv_from(user_request_buffer.buf_mut()) {
            Ok(x) => x,
            Err(e) => { eprintln!("recv failed: {e}"); continue; }
        };

        let user_request_packet = match DnsPacket::from_buffer(&mut user_request_buffer) {
            Ok(p) => p,
            Err(e) => { eprintln!("bad packet from {src}: {e}"); continue; }
        };
        
        let mut answers = vec![];
        for question in &user_request_packet.questions {
            let server_response = lookup(question.name.clone(), question.qtype, upstream_resolver)?;
            for answer in server_response.answers {
                answers.push(answer);
            }
        }

        let mut response = build_response(&user_request_packet, upstream_resolver);
        let buffer = match serialize(&mut response) {
            Ok(b) => b,
            Err(e) => { eprintln!("couldn't serialize response for {src}: {e}"); continue; }
        };

        if let Err(e) = socket.send_to(buffer.written(), src) {
            eprintln!("send to {src} failed: {e}");
        }
    }
}