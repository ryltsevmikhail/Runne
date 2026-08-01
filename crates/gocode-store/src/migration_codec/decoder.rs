struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, MigrationCodecError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, MigrationCodecError> {
        Ok(u16::from_be_bytes(self.read_exact::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, MigrationCodecError> {
        Ok(u32::from_be_bytes(self.read_exact::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, MigrationCodecError> {
        Ok(u64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_i64(&mut self) -> Result<i64, MigrationCodecError> {
        Ok(i64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MigrationCodecError> {
        self.read_exact::<N>()
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, MigrationCodecError> {
        let length = usize::from(self.read_u16()?);
        let end = self
            .position
            .checked_add(length)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position = end;
        String::from_utf8(value.to_vec()).map_err(|_| MigrationCodecError::InvalidUtf8 { field })
    }

    fn read_blob(&mut self, field: &'static str) -> Result<&'a [u8], MigrationCodecError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| MigrationCodecError::Oversized {
                field,
                max: usize::MAX,
                actual: usize::MAX,
            })?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], MigrationCodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        let mut output = [0; N];
        output.copy_from_slice(value);
        self.position = end;
        Ok(output)
    }

    fn finish(self) -> Result<(), MigrationCodecError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MigrationCodecError::TrailingBytes {
                remaining: self.bytes.len() - self.position,
            })
        }
    }
}
