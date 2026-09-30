use crate::errors::TazuneError;

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255; // wire format, including length bytes and the root label
const MAX_JUMPS: usize = 5;

pub struct BytePacketBuffer {
    pub buf: Vec<u8>,
    pub pos: usize,
    pub max_length: usize,
}

impl BytePacketBuffer {
    pub fn new(max_len: usize) -> BytePacketBuffer {
        BytePacketBuffer {
            buf: vec![],
            pos: 0,
            max_length: max_len,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<(), TazuneError> {
        if self.pos + steps >= self.max_length {
            return Err(TazuneError::EndOfBufferReached { buffer_length: self.max_length });
        }
        self.pos += steps;
        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), TazuneError> {
        if pos > self.max_length || pos < 0 {
            self.pos = pos;
            return Ok(());
        }
        return Err(TazuneError::IndexOutOfRange { range_start: 0, range_end: self.max_length });
    }

    pub fn read(&mut self) -> Result<u8, TazuneError> {
        if self.pos >= 512 {
            return Err(TazuneError::EndOfBufferReached { buffer_length: self.max_length });
        }
        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    pub fn get(&mut self, pos: usize) -> Result<u8, TazuneError> {
        if pos >= 512 {
            return Err(TazuneError::EndOfBufferReached { buffer_length: self.max_length });
        }
        Ok(self.buf[pos])
    }

    pub fn get_range(&mut self, start: usize, len: usize) -> Result<&[u8], TazuneError> {
        if start + len >= 512 {
            return Err(TazuneError::EndOfBufferReached { buffer_length: self.max_length });
        }
        Ok(&self.buf[start..start + (len as usize)])
    }

    pub fn read_u16(&mut self) -> Result<u16, TazuneError> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, TazuneError> {
        let res =
            ((self.read()? as u32) << 24) |
            ((self.read()? as u32) << 16) |
            ((self.read()? as u32) << 8) |
            ((self.read()? as u32) << 0);

        Ok(res)
    }

    // Will take something like [3]www[6]google[3]com[0] and returns www.google.com.
    pub fn read_qname(&mut self) -> Result<String, TazuneError> {
        let mut result = String::with_capacity(64);
        let mut pos = self.pos();

        // Where the caller's cursor should end up: right after the first
        // compression pointer, or after the terminating zero byte.
        let mut resume_pos: Option<usize> = None;
        let mut jumps = 0;
        let mut wire_len = 1; // the terminating root label

        loop {
            // We're always at the start of a label here.
            let len = self.get(pos)?;

            match len & 0xc0 {
                // Compression pointer: 14-bit offset across two bytes.
                0xc0 => {
                    let b2 = self.get(pos + 1)?;
                    resume_pos.get_or_insert(pos + 2);

                    jumps += 1;
                    if jumps > MAX_JUMPS {
                        return Err(TazuneError::MaxJumpsPerformed);
                    }

                    pos = (((len & 0x3f) as usize) << 8) | (b2 as usize);
                }

                // Ordinary label.
                0x00 => {
                    pos += 1;
                    if len == 0 {
                        break; // root label, name is complete
                    }

                    let len = len as usize; // already guaranteed <= 63 by the mask
                    debug_assert!(len <= MAX_LABEL_LEN);

                    wire_len += len + 1;
                    if wire_len > MAX_NAME_LEN {
                        return Err(TazuneError::QNameTooLong {max_name_len: MAX_NAME_LEN, name_len: wire_len });
                    }

                    if !result.is_empty() {
                        result.push('.');
                    }

                    for &b in self.get_range(pos, len)? {
                        match b {
                            // Escape so the output is unambiguous (RFC 1035 §5.1).
                            b'.' | b'\\' => {
                                result.push('\\');
                                result.push(b as char);
                            }
                            0x21..=0x7e => result.push(b.to_ascii_lowercase() as char),
                            _ => result.push_str(&format!("\\{:03}", b)),
                        }
                    }

                    pos += len;
                }

                // 0x40 / 0x80 label types are reserved.
                _ => {
                    return Err(TazuneError::InvalidLabelType { label_type: len & 0xc0 });
                }
            }
        }

        self.seek(resume_pos.unwrap_or(pos))?;
        Ok(result)
    }
}
