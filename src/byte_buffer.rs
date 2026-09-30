use crate::errors::TazuneError;

pub struct BytePacketBuffer {
    pub buf: Vec<u8>,
    pub pos: usize,
    pub max_length: usize
}

impl BytePacketBuffer {
    pub fn new(max_len: usize) -> BytePacketBuffer {
        BytePacketBuffer {
            buf: vec![],
            pos: 0,
            max_length: max_len
        }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn step(&mut self, steps: usize) -> Result<(), TazuneError> {
        if self.pos + steps >= self.max_length {
            return Err(TazuneError::EndOfBufferReached { buffer_length: self.max_length });
        }
        self.pos+=steps;
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
        Ok(&self.buf[start..start + len as usize])
    }

    pub fn read_u16(&mut self) -> Result<u16, TazuneError> {
        let res = ((self.read()? as u16) << 8) | (self.read()? as u16);

        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, TazuneError> {
        let res = ((self.read()? as u32) << 24)
            | ((self.read()? as u32) << 16)
            | ((self.read()? as u32) << 8)
            | ((self.read()? as u32) << 0);

        Ok(res)
    }


    // Will take something like [3]www[6]google[3]com[0] and returns www.google.com.
    pub fn read_qname(&mut self) -> Result<String, TazuneError> {
        let mut result = String::new();
        let mut pos = self.pos();

        // track whether or not we've jumped
        let mut jumped = false;
        let max_jumps = 5;
        let mut jumps_performed = 0;

        // Our delimiter which we append for each label. Since we don't want a
        // dot at the beginning of the domain name we'll leave it empty for now
        // and set it to "." at the end of the first iteration.
        let mut delim = "";
        loop {
            // Dns Packets are untrusted data, so we need to be paranoid. Someone
            // can craft a packet with a cycle in the jump instructions. This guards
            // against such packets.
            if jumps_performed > max_jumps {
                return Err(TazuneError::MaxJumpsPerformed);
            }

            // At this point, we're always at the beginning of a label. Recall
            // that labels start with a length byte.
            let len = self.get(pos)?;

            // If len has the two most significant bit are set, it represents a
            // jump to some other offset in the packet:
            if (len & 0xC0) == 0xC0 {
                // Update the buffer position to a point past the current
                // label. We don't need to touch it any further.
                if !jumped {
                    self.seek(pos + 2)?;
                }

                // Read another byte, calculate offset and perform the jump by
                // updating our local position variable
                let b2 = self.get(pos + 1)? as u16;
                let offset = (((len as u16) ^ 0xC0) << 8) | b2;
                pos = offset as usize;

                // Indicate that a jump was performed.
                jumped = true;
                jumps_performed += 1;

                continue;
            }
            // The base scenario, where we're reading a single label and
            // appending it to the output:
            else {
                // Move a single byte forward to move past the length byte.
                pos += 1;

                // Domain names are terminated by an empty label of length 0,
                // so if the length is zero we're done.
                if len == 0 {
                    break;
                }

                // Append the delimiter to our output buffer first.
                result.push_str(delim);

                // Extract the actual ASCII bytes for this label and append them
                // to the output buffer.
                let str_buffer = self.get_range(pos, len as usize)?;
                result.push_str(&String::from_utf8_lossy(str_buffer).to_lowercase());

                delim = ".";

                // Move forward the full length of the label.
                pos += len as usize;
            }
        }

        if !jumped {
            self.seek(pos)?;
        }

        Ok(result)
    }
}