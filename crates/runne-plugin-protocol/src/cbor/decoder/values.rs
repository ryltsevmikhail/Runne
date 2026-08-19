impl<'a> CborDecoder<'a> {

    pub fn read_unsigned(&mut self, max: u64) -> Result<u64, DecodeError> {
        let (_add, value) = self.read_initial(MajorType::Unsigned)?;
        if value > max {
            return Err(DecodeError::LimitExceeded {
                limit: "unsigned".into(),
                max: max as usize,
                actual: value as usize,
            });
        }
        Ok(value)
    }

    pub fn read_signed(&mut self, min: i64, max: i64) -> Result<i64, DecodeError> {
        let b = self.peek()?;
        match MajorType::from_byte(b) {
            MajorType::Unsigned => {
                let v = self.read_unsigned(max as u64)?;
                if v > max as u64 {
                    return Err(DecodeError::LimitExceeded {
                        limit: "signed".into(),
                        max: max as usize,
                        actual: v as usize,
                    });
                }
                Ok(v as i64)
            }
            MajorType::Negative => {
                let (_add, value) = self.read_initial(MajorType::Negative)?;
                let v = -((value as i64) + 1);
                if v < min {
                    return Err(DecodeError::LimitExceeded {
                        limit: "signed".into(),
                        max: max as usize,
                        actual: v as usize,
                    });
                }
                Ok(v)
            }
            other => Err(DecodeError::UnexpectedMajorType {
                offset: self.pos,
                expected: MajorType::Unsigned,
                actual: other,
            }),
        }
    }

    pub fn read_byte_string(&mut self, max_bytes: usize) -> Result<&'a [u8], DecodeError> {
        let offset = self.pos;
        let (_add, len) = self.read_initial(MajorType::ByteString)?;
        if len as usize > max_bytes {
            return Err(DecodeError::StringTooLong {
                offset,
                max: max_bytes,
                actual: len as usize,
            });
        }
        if self.remaining() < len as usize {
            return Err(DecodeError::TruncatedCbor { offset: self.pos });
        }
        let start = self.pos;
        self.advance(len as usize);
        Ok(&self.data[start..start + len as usize])
    }

    pub fn read_text_string(&mut self, max_bytes: usize) -> Result<&'a str, DecodeError> {
        let offset = self.pos;
        let (_add, len) = self.read_initial(MajorType::TextString)?;
        if len as usize > max_bytes {
            return Err(DecodeError::StringTooLong {
                offset,
                max: max_bytes,
                actual: len as usize,
            });
        }
        if self.remaining() < len as usize {
            return Err(DecodeError::TruncatedCbor { offset: self.pos });
        }
        let start = self.pos;
        self.advance(len as usize);
        let bytes = &self.data[start..start + len as usize];
        std::str::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8 { offset })
    }

    pub fn read_array_header(&mut self, max_items: u32) -> Result<u64, DecodeError> {
        let (_add, len) = self.read_initial(MajorType::Array)?;
        if len > max_items as u64 {
            return Err(DecodeError::LimitExceeded {
                limit: "array items".into(),
                max: max_items as usize,
                actual: len as usize,
            });
        }
        Ok(len)
    }

    pub fn read_map_header(&mut self, max_items: u32) -> Result<u64, DecodeError> {
        let (_add, len) = self.read_initial(MajorType::Map)?;
        if len > max_items as u64 {
            return Err(DecodeError::LimitExceeded {
                limit: "map items".into(),
                max: max_items as usize,
                actual: len as usize,
            });
        }
        Ok(len)
    }

    pub fn read_bool(&mut self) -> Result<bool, DecodeError> {
        let b = self.peek()?;
        match b {
            0xf4 => {
                self.advance(1);
                Ok(false)
            }
            0xf5 => {
                self.advance(1);
                Ok(true)
            }
            _ => Err(DecodeError::UnexpectedMajorType {
                offset: self.pos,
                expected: MajorType::Simple,
                actual: MajorType::from_byte(b),
            }),
        }
    }

    pub fn read_null(&mut self) -> Result<(), DecodeError> {
        let b = self.peek()?;
        if b == 0xf6 {
            self.advance(1);
            Ok(())
        } else {
            Err(DecodeError::UnexpectedMajorType {
                offset: self.pos,
                expected: MajorType::Simple,
                actual: MajorType::from_byte(b),
            })
        }
    }

    pub fn read_optional_bool(&mut self) -> Result<Option<bool>, DecodeError> {
        let b = self.peek()?;
        match b {
            0xf4 => {
                self.advance(1);
                Ok(Some(false))
            }
            0xf5 => {
                self.advance(1);
                Ok(Some(true))
            }
            0xf6 => {
                self.advance(1);
                Ok(None)
            }
            _ => Err(DecodeError::UnexpectedMajorType {
                offset: self.pos,
                expected: MajorType::Simple,
                actual: MajorType::from_byte(b),
            }),
        }
    }

    pub fn read_uuid_bytes(&mut self) -> Result<[u8; 16], DecodeError> {
        let bytes = self.read_byte_string(16)?;
        if bytes.len() != 16 {
            return Err(DecodeError::TruncatedCbor { offset: self.pos });
        }
        let mut out = [0u8; 16];
        out.copy_from_slice(bytes);
        Ok(out)
    }

    /// Check for major type 6 (tag) at current position.
    pub fn reject_tags(&mut self) -> Result<(), DecodeError> {
        let b = self.peek()?;
        if MajorType::from_byte(b) as u8 == 6 {
            return Err(DecodeError::TagNotAllowed {
                offset: self.pos,
                tag: 0,
            });
        }
        Ok(())
    }

    /// Check the current offset is at the end of the buffer.
    pub fn expect_eof(&self) -> Result<(), DecodeError> {
        if self.pos < self.data.len() {
            return Err(DecodeError::TrailingBytes {
                offset: self.pos,
                count: self.data.len() - self.pos,
            });
        }
        Ok(())
    }

    /// Current byte offset.
    pub fn position(&self) -> usize {
        self.pos
    }
}
