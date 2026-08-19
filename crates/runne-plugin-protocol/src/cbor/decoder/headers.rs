impl<'a> CborDecoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn peek(&self) -> Result<u8, DecodeError> {
        self.data
            .get(self.pos)
            .copied()
            .ok_or(DecodeError::TruncatedCbor { offset: self.pos })
    }
    fn advance(&mut self, n: usize) {
        self.pos += n;
    }

    fn read_initial(&mut self, expected_major: MajorType) -> Result<(u8, u64), DecodeError> {
        let b = self.peek()?;
        let major = MajorType::from_byte(b);
        if major != expected_major {
            return Err(DecodeError::UnexpectedMajorType {
                offset: self.pos,
                expected: expected_major,
                actual: major,
            });
        }
        let additional = b & 0x1f;
        let value = self.read_argument(additional)?;
        Ok((additional, value))
    }

    fn read_argument(&mut self, additional: u8) -> Result<u64, DecodeError> {
        self.advance(1);
        Ok(match additional {
            0..=23 => additional as u64,
            24 => {
                if self.remaining() < 1 {
                    return Err(DecodeError::TruncatedCbor { offset: self.pos });
                }
                // Deterministic: value >= 24 must not fit in <24
                let v = self.data[self.pos] as u64;
                if v < 24 {
                    return Err(DecodeError::NonCanonicalEncoding { offset: self.pos });
                }
                self.advance(1);
                v
            }
            25 => {
                if self.remaining() < 2 {
                    return Err(DecodeError::TruncatedCbor { offset: self.pos });
                }
                let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]) as u64;
                if v <= 0xFF {
                    return Err(DecodeError::NonCanonicalEncoding { offset: self.pos });
                }
                self.advance(2);
                v
            }
            26 => {
                if self.remaining() < 4 {
                    return Err(DecodeError::TruncatedCbor { offset: self.pos });
                }
                let v = u32::from_be_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                    self.data[self.pos + 2],
                    self.data[self.pos + 3],
                ]) as u64;
                if v <= 0xFFFF {
                    return Err(DecodeError::NonCanonicalEncoding { offset: self.pos });
                }
                self.advance(4);
                v
            }
            27 => {
                if self.remaining() < 8 {
                    return Err(DecodeError::TruncatedCbor { offset: self.pos });
                }
                let v = u64::from_be_bytes([
                    self.data[self.pos],
                    self.data[self.pos + 1],
                    self.data[self.pos + 2],
                    self.data[self.pos + 3],
                    self.data[self.pos + 4],
                    self.data[self.pos + 5],
                    self.data[self.pos + 6],
                    self.data[self.pos + 7],
                ]);
                if v <= 0xFFFF_FFFF {
                    return Err(DecodeError::NonCanonicalEncoding { offset: self.pos });
                }
                self.advance(8);
                v
            }
            28..=30 => {
                return Err(DecodeError::IndefiniteLengthNotAllowed {
                    offset: self.pos - 1,
                });
            }
            31 => {
                return Err(DecodeError::IndefiniteLengthNotAllowed {
                    offset: self.pos - 1,
                });
            }
            _ => unreachable!(),
        })
    }
}
