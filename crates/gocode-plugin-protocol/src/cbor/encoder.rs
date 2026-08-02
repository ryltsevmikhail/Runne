/// Deterministic CBOR encoder.
///
/// Produces RFC 8949 Core Deterministic Encoding:
/// - Integers use shortest form
/// - Map keys encoded in bytewise lexicographic order (caller sorts before writing)
/// - No floats, tags, or indefinite-length
#[derive(Debug)]
pub struct CborEncoder {
    buf: Vec<u8>,
}

impl CborEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }
    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    fn write_initial_byte(&mut self, major: u8, additional: u8) {
        self.buf.push((major << 5) | (additional & 0x1f));
    }

    fn write_argument(&mut self, arg: u64) {
        // Deterministic: use shortest encoding
        if arg <= 23 {
            self.buf.last_mut().map(|b| *b |= arg as u8);
        } else if arg <= 0xFF {
            self.buf.last_mut().map(|b| *b |= 24);
            self.buf.push(arg as u8);
        } else if arg <= 0xFFFF {
            self.buf.last_mut().map(|b| *b |= 25);
            self.buf.extend_from_slice(&(arg as u16).to_be_bytes());
        } else if arg <= 0xFFFF_FFFF {
            self.buf.last_mut().map(|b| *b |= 26);
            self.buf.extend_from_slice(&(arg as u32).to_be_bytes());
        } else {
            self.buf.last_mut().map(|b| *b |= 27);
            self.buf.extend_from_slice(&arg.to_be_bytes());
        }
    }

    pub fn write_unsigned(&mut self, value: u64) {
        self.write_initial_byte(0, 0);
        self.write_argument(value);
    }

    pub fn write_negative(&mut self, value: i64) {
        assert!(value < 0, "use write_unsigned for non-negative values");
        let n = (-value - 1) as u64;
        self.write_initial_byte(1, 0);
        self.write_argument(n);
    }

    pub fn write_byte_string(&mut self, data: &[u8]) {
        let len = data.len() as u64;
        self.write_initial_byte(2, 0);
        self.write_argument(len);
        self.buf.extend_from_slice(data);
    }

    pub fn write_text_string(&mut self, text: &str) {
        let len = text.len() as u64;
        self.write_initial_byte(3, 0);
        self.write_argument(len);
        self.buf.extend_from_slice(text.as_bytes());
    }

    pub fn write_array_header(&mut self, len: u64) {
        self.write_initial_byte(4, 0);
        self.write_argument(len);
    }

    pub fn write_map_header(&mut self, len: u64) {
        self.write_initial_byte(5, 0);
        self.write_argument(len);
    }

    pub fn write_bool(&mut self, value: bool) {
        if value {
            self.buf.push(0xf5);
        } else {
            self.buf.push(0xf4);
        }
    }

    pub fn write_null(&mut self) {
        self.buf.push(0xf6);
    }

    /// Write a 16-byte UUID as a tagged byte string.
    pub fn write_uuid_bytes(&mut self, bytes: &[u8; 16]) {
        self.write_byte_string(bytes);
    }
}
