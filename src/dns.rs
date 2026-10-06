use crate::byte_buffer::BytePacketBuffer;
use crate::errors::TazuneError;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResultCode {
    UNKNOWN(u8),
    NOERROR,  // 0
    FORMERR,  // 1
    SERVFAIL, // 2
    NXDOMAIN, // 3
    NOTIMP,   // 4
    REFUSED,  // 5
}

impl ResultCode {
    pub fn to_num(&self) -> u8 {
        match *self {
            ResultCode::UNKNOWN(x) => x,
            ResultCode::NOERROR => 0,
            ResultCode::FORMERR => 1,
            ResultCode::SERVFAIL => 2,
            ResultCode::NXDOMAIN => 3,
            ResultCode::NOTIMP => 4,
            ResultCode::REFUSED => 5,
        }
    }

    pub fn from_num(num: u8) -> ResultCode {
        match num {
            0 => ResultCode::NOERROR,
            1 => ResultCode::FORMERR,
            2 => ResultCode::SERVFAIL,
            3 => ResultCode::NXDOMAIN,
            4 => ResultCode::NOTIMP,
            5 => ResultCode::REFUSED,
            _ => ResultCode::UNKNOWN(num),
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone, Hash, Copy)]
pub enum QueryType {
    UNKNOWN(u16),
    A,     // 1
    NS,    // 2
    CNAME, // 5
    MX,    // 15
    AAAA,  // 28
}

impl QueryType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryType::UNKNOWN(x) => x,
            QueryType::A => 1,
            QueryType::NS => 2,
            QueryType::CNAME => 5,
            QueryType::MX => 15,
            QueryType::AAAA => 28,
        }
    }

    pub fn from_num(num: u16) -> QueryType {
        match num {
            1 => QueryType::A,
            2 => QueryType::NS,
            5 => QueryType::CNAME,
            15 => QueryType::MX,
            28 => QueryType::AAAA,
            _ => QueryType::UNKNOWN(num),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DnsHeader {
    pub id: u16, // 16 bits

    pub recursion_desired: bool,    // 1 bit
    pub truncated_message: bool,    // 1 bit
    pub authoritative_answer: bool, // 1 bit
    pub opcode: u8,                 // 4 bits
    pub response: bool,             // 1 bit

    pub rescode: ResultCode,       // 4 bits
    pub checking_disabled: bool,   // 1 bit
    pub authed_data: bool,         // 1 bit
    pub z: bool,                   // 1 bit
    pub recursion_available: bool, // 1 bit

    pub questions: u16,             // 16 bits
    pub answers: u16,               // 16 bits
    pub authoritative_entries: u16, // 16 bits
    pub resource_entries: u16,      // 16 bits
}

impl DnsHeader {
    pub fn new() -> DnsHeader {
        DnsHeader {
            id: 0,

            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: false,

            rescode: ResultCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsHeader, TazuneError> {
        let id = buffer.read_u16()?;

        let flags = buffer.read_u16()?;
        let a = (flags >> 8) as u8;
        let b = (flags & 0xFF) as u8;

        Ok(DnsHeader {
            id,

            recursion_desired: (a & (1 << 0)) > 0,
            truncated_message: (a & (1 << 1)) > 0,
            authoritative_answer: (a & (1 << 2)) > 0,
            opcode: (a >> 3) & 0x0F,
            response: (a & (1 << 7)) > 0,

            rescode: ResultCode::from_num(b & 0x0F),
            checking_disabled: (b & (1 << 4)) > 0,
            authed_data: (b & (1 << 5)) > 0,
            z: (b & (1 << 6)) > 0,
            recursion_available: (b & (1 << 7)) > 0,

            questions: buffer.read_u16()?,
            answers: buffer.read_u16()?,
            authoritative_entries: buffer.read_u16()?,
            resource_entries: buffer.read_u16()?,
        })
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), TazuneError> {
        buffer.write_u16(self.id)?;

        buffer.write_u8(
            (self.recursion_desired as u8)
                | ((self.truncated_message as u8) << 1)
                | ((self.authoritative_answer as u8) << 2)
                | ((self.opcode & 0x0F) << 3)
                | ((self.response as u8) << 7) as u8,
        )?;

        buffer.write_u8(
            (self.rescode.to_num())
                | ((self.checking_disabled as u8) << 4)
                | ((self.authed_data as u8) << 5)
                | ((self.z as u8) << 6)
                | ((self.recursion_available as u8) << 7),
        )?;

        buffer.write_u16(self.questions)?;
        buffer.write_u16(self.answers)?;
        buffer.write_u16(self.authoritative_entries)?;
        buffer.write_u16(self.resource_entries)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: QueryType,
}

impl DnsQuestion {
    pub fn new(name: String, qtype: QueryType) -> DnsQuestion {
        DnsQuestion { name, qtype }
    }

    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsQuestion, TazuneError> {
        let name = buffer.read_qname()?; // qname
        let qtype = QueryType::from_num(buffer.read_u16()?); // qtype
        let _ = buffer.read_u16()?; // class

        Ok(DnsQuestion { name, qtype })
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<(), TazuneError> {
        buffer.write_qname(&self.name)?;

        let typenum = self.qtype.to_num();
        buffer.write_u16(typenum)?;
        buffer.write_u16(1)?;

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[allow(dead_code)]
pub enum DnsRecord {
    UNKNOWN {
        domain: String,
        qtype: u16,
        data: Vec<u8>,
        ttl: u32,
    }, // 0
    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32,
    }, // 1
    NS {
        domain: String,
        host: String,
        ttl: u32,
    }, // 2
    CNAME {
        domain: String,
        host: String,
        ttl: u32,
    }, // 5
    MX {
        domain: String,
        priority: u16,
        host: String,
        ttl: u32,
    }, // 15
    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32,
    }, // 28
}

// Writes a u16 length placeholder, runs `f` to write the record data and then
// patches the placeholder with the number of bytes `f` wrote.
fn write_with_len(
    buffer: &mut BytePacketBuffer,
    f: impl FnOnce(&mut BytePacketBuffer) -> Result<(), TazuneError>,
) -> Result<(), TazuneError> {
    let pos = buffer.pos();
    buffer.write_u16(0)?;

    f(buffer)?;

    let size = buffer.pos() - (pos + 2);
    buffer.set_u16(pos, size as u16)
}

impl DnsRecord {
    pub fn read(buffer: &mut BytePacketBuffer) -> Result<DnsRecord, TazuneError> {
        let domain = buffer.read_qname()?;

        let qtype_num = buffer.read_u16()?;
        let qtype = QueryType::from_num(qtype_num);
        let _ = buffer.read_u16()?;
        let ttl = buffer.read_u32()?;
        let data_len = buffer.read_u16()? as usize;
        let rdata_end = buffer.pos() + data_len;

        let record = match qtype {
            QueryType::A => {
                let addr = Ipv4Addr::from(buffer.read_u32()?);

                DnsRecord::A {
                    domain,
                    addr,
                    ttl,
                }
            }
            QueryType::AAAA => {
                let mut octets = [0u8; 16];
                for octet in octets.iter_mut() {
                    *octet = buffer.read()?;
                }
                let addr = Ipv6Addr::from(octets);

                DnsRecord::AAAA {
                    domain,
                    addr,
                    ttl,
                }
            }
            QueryType::NS => {
                let ns = buffer.read_qname()?;

                DnsRecord::NS {
                    domain,
                    host: ns,
                    ttl,
                }
            }
            QueryType::CNAME => {
                let cname = buffer.read_qname()?;

                DnsRecord::CNAME {
                    domain,
                    host: cname,
                    ttl,
                }
            }
            QueryType::MX => {
                let priority = buffer.read_u16()?;
                let mx = buffer.read_qname()?;

                DnsRecord::MX {
                    domain,
                    priority,
                    host: mx,
                    ttl,
                }
            }
            QueryType::UNKNOWN(_) => {
                let data = buffer.get_range(buffer.pos(), data_len)?.to_vec();

                DnsRecord::UNKNOWN {
                    domain,
                    qtype: qtype_num,
                    data,
                    ttl,
                }
            }
        };

        // Always land exactly after the record, whatever the parsing above consumed.
        buffer.seek(rdata_end)?;

        Ok(record)
    }

    pub fn ttl(&self) -> u32 {
        match *self {
            DnsRecord::UNKNOWN { ttl, .. }
            | DnsRecord::A { ttl, .. }
            | DnsRecord::NS { ttl, .. }
            | DnsRecord::CNAME { ttl, .. }
            | DnsRecord::MX { ttl, .. }
            | DnsRecord::AAAA { ttl, .. } => ttl,
        }
    }

    // A copy of this record with a different TTL, used when serving cached records.
    pub fn with_ttl(&self, new_ttl: u32) -> DnsRecord {
        let mut record = self.clone();
        match record {
            DnsRecord::UNKNOWN { ref mut ttl, .. }
            | DnsRecord::A { ref mut ttl, .. }
            | DnsRecord::NS { ref mut ttl, .. }
            | DnsRecord::CNAME { ref mut ttl, .. }
            | DnsRecord::MX { ref mut ttl, .. }
            | DnsRecord::AAAA { ref mut ttl, .. } => *ttl = new_ttl,
        }
        record
    }

    pub fn write(&self, buffer: &mut BytePacketBuffer) -> Result<usize, TazuneError> {
        let start_pos = buffer.pos();

        match *self {
            DnsRecord::A {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::A.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(4)?;

                let octets = addr.octets();
                buffer.write_u8(octets[0])?;
                buffer.write_u8(octets[1])?;
                buffer.write_u8(octets[2])?;
                buffer.write_u8(octets[3])?;
            }
            DnsRecord::NS {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::NS.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                write_with_len(buffer, |buffer| buffer.write_qname(host))?;
            }
            DnsRecord::CNAME {
                ref domain,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::CNAME.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                write_with_len(buffer, |buffer| buffer.write_qname(host))?;
            }
            DnsRecord::MX {
                ref domain,
                priority,
                ref host,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::MX.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;

                write_with_len(buffer, |buffer| {
                    buffer.write_u16(priority)?;
                    buffer.write_qname(host)
                })?;
            }
            DnsRecord::AAAA {
                ref domain,
                ref addr,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(QueryType::AAAA.to_num())?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(16)?;

                for octet in &addr.segments() {
                    buffer.write_u16(*octet)?;
                }
            }
            DnsRecord::UNKNOWN {
                ref domain,
                qtype,
                ref data,
                ttl,
            } => {
                buffer.write_qname(domain)?;
                buffer.write_u16(qtype)?;
                buffer.write_u16(1)?;
                buffer.write_u32(ttl)?;
                buffer.write_u16(data.len() as u16)?;

                for b in data {
                    buffer.write_u8(*b)?;
                }
            }
        }

        Ok(buffer.pos() - start_pos)
    }
}

#[derive(Clone, Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub resources: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> DnsPacket {
        DnsPacket {
            header: DnsHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authorities: Vec::new(),
            resources: Vec::new(),
        }
    }

    pub fn from_buffer(buffer: &mut BytePacketBuffer) -> Result<DnsPacket, TazuneError> {
        let mut result = DnsPacket::new();
        result.header = DnsHeader::read(buffer)?;

        for _ in 0..result.header.questions {
            let question = DnsQuestion::read(buffer)?;
            result.questions.push(question);
        }

        for _ in 0..result.header.answers {
            let rec = DnsRecord::read(buffer)?;
            result.answers.push(rec);
        }
        for _ in 0..result.header.authoritative_entries {
            let rec = DnsRecord::read(buffer)?;
            result.authorities.push(rec);
        }
        for _ in 0..result.header.resource_entries {
            let rec = DnsRecord::read(buffer)?;
            result.resources.push(rec);
        }

        Ok(result)
    }

    pub fn write(&mut self, buffer: &mut BytePacketBuffer) -> Result<(), TazuneError> {
        self.header.questions = self.questions.len() as u16;
        self.header.answers = self.answers.len() as u16;
        self.header.authoritative_entries = self.authorities.len() as u16;
        self.header.resource_entries = self.resources.len() as u16;

        self.header.write(buffer)?;

        for question in &self.questions {
            question.write(buffer)?;
        }
        for rec in &self.answers {
            rec.write(buffer)?;
        }
        for rec in &self.authorities {
            rec.write(buffer)?;
        }
        for rec in &self.resources {
            rec.write(buffer)?;
        }

        Ok(())
    }
}
