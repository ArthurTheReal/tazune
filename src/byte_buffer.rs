use crate::errors::TazuneError;

const MAX_LABEL_LEN: usize = 63;
const MAX_NAME_LEN: usize = 255; // wire format, including length bytes and the root label
const MAX_JUMPS: usize = 5;

pub struct BytePacketBuffer {
    buf: Vec<u8>,
    pos: usize,
}

impl BytePacketBuffer {
    pub fn new(max_len: usize) -> BytePacketBuffer {
        BytePacketBuffer {
            buf: vec![0; max_len],
            pos: 0,
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    // Everything written to the buffer so far.
    pub fn written(&self) -> &[u8] {
        &self.buf[..self.pos]
    }

    // The whole underlying buffer
    pub fn buf_mut(&mut self) -> &mut [u8] {
        &mut self.buf
    }

    pub fn step(&mut self, steps: usize) -> Result<(), TazuneError> {
        if self.pos.saturating_add(steps) > self.buf.len() {
            return Err(TazuneError::EndOfBufferReached {
                buffer_length: self.buf.len(),
            });
        }
        self.pos += steps;
        Ok(())
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), TazuneError> {
        if pos > self.buf.len() {
            return Err(TazuneError::IndexOutOfRange {
                range_start: 0,
                range_end: self.buf.len(),
            });
        }
        self.pos = pos;
        Ok(())
    }

    pub fn read(&mut self) -> Result<u8, TazuneError> {
        let res = self.get(self.pos)?;
        self.pos += 1;

        Ok(res)
    }

    pub fn get(&self, pos: usize) -> Result<u8, TazuneError> {
        self.buf
            .get(pos)
            .copied()
            .ok_or(TazuneError::EndOfBufferReached {
                buffer_length: self.buf.len(),
            })
    }

    pub fn get_range(&self, start: usize, len: usize) -> Result<&[u8], TazuneError> {
        self.buf
            .get(start..start.saturating_add(len))
            .ok_or(TazuneError::EndOfBufferReached {
                buffer_length: self.buf.len(),
            })
    }

    pub fn read_u16(&mut self) -> Result<u16, TazuneError> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, TazuneError> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | (self.read()? as u32);

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
                        return Err(TazuneError::QNameTooLong {
                            max_name_len: MAX_NAME_LEN,
                            name_len: wire_len,
                        });
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
                    return Err(TazuneError::InvalidLabelType {
                        label_type: len & 0xc0,
                    });
                }
            }
        }

        self.seek(resume_pos.unwrap_or(pos))?;
        Ok(result)
    }

    pub fn write_u8(&mut self, val: u8) -> Result<(), TazuneError> {
        self.set(self.pos, val)?;
        self.pos += 1;

        Ok(())
    }

    pub fn write_u16(&mut self, val: u16) -> Result<(), TazuneError> {
        self.write_u8((val >> 8) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_u32(&mut self, val: u32) -> Result<(), TazuneError> {
        self.write_u8(((val >> 24) & 0xFF) as u8)?;
        self.write_u8(((val >> 16) & 0xFF) as u8)?;
        self.write_u8(((val >> 8) & 0xFF) as u8)?;
        self.write_u8((val & 0xFF) as u8)?;

        Ok(())
    }

    pub fn write_qname(&mut self, qname: &str) -> Result<(), TazuneError> {
        for label in qname.split('.') {
            let len = label.len();
            if len == 0 {
                continue; // empty name or trailing dot, the root label is written below
            }
            if len > 0x3f {
                return Err(TazuneError::LabelTooLong { label_len: len });
            }

            self.write_u8(len as u8)?;
            for b in label.as_bytes() {
                self.write_u8(*b)?;
            }
        }

        self.write_u8(0)?;

        Ok(())
    }

    pub fn set(&mut self, pos: usize, val: u8) -> Result<(), TazuneError> {
        let buffer_length = self.buf.len();
        let slot = self
            .buf
            .get_mut(pos)
            .ok_or(TazuneError::EndOfBufferReached { buffer_length })?;
        *slot = val;

        Ok(())
    }

    pub fn set_u16(&mut self, pos: usize, val: u16) -> Result<(), TazuneError> {
        self.set(pos, (val >> 8) as u8)?;
        self.set(pos + 1, (val & 0xFF) as u8)?;

        Ok(())
    }
}
