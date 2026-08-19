// ── tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ─── Encoder tests ───────────────────────────────────────────────────

    #[test]
    fn test_encode_unsigned_zero() {
        let mut e = CborEncoder::new();
        e.write_unsigned(0);
        assert_eq!(e.into_bytes(), vec![0x00]);
    }

    #[test]
    fn test_encode_unsigned_23() {
        let mut e = CborEncoder::new();
        e.write_unsigned(23);
        assert_eq!(e.into_bytes(), vec![0x17]);
    }

    #[test]
    fn test_encode_unsigned_24() {
        let mut e = CborEncoder::new();
        e.write_unsigned(24);
        assert_eq!(e.into_bytes(), vec![0x18, 0x18]);
    }

    #[test]
    fn test_encode_unsigned_256() {
        let mut e = CborEncoder::new();
        e.write_unsigned(256);
        assert_eq!(e.into_bytes(), vec![0x19, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_negative_minus_1() {
        let mut e = CborEncoder::new();
        e.write_negative(-1);
        assert_eq!(e.into_bytes(), vec![0x20]);
    }

    #[test]
    fn test_encode_byte_string() {
        let mut e = CborEncoder::new();
        e.write_byte_string(b"hello");
        assert_eq!(e.into_bytes(), vec![0x45, b'h', b'e', b'l', b'l', b'o']);
    }

    #[test]
    fn test_encode_text_string() {
        let mut e = CborEncoder::new();
        e.write_text_string("hi");
        assert_eq!(e.into_bytes(), vec![0x62, b'h', b'i']);
    }

    #[test]
    fn test_encode_array() {
        let mut e = CborEncoder::new();
        e.write_array_header(2);
        e.write_unsigned(1);
        e.write_unsigned(2);
        assert_eq!(e.into_bytes(), vec![0x82, 0x01, 0x02]);
    }

    #[test]
    fn test_encode_map() {
        let mut e = CborEncoder::new();
        e.write_map_header(1);
        e.write_unsigned(1);
        e.write_text_string("v");
        assert_eq!(e.into_bytes(), vec![0xA1, 0x01, 0x61, b'v']);
    }

    #[test]
    fn test_encode_bool_and_null() {
        let mut e = CborEncoder::new();
        e.write_bool(true);
        e.write_bool(false);
        e.write_null();
        assert_eq!(e.into_bytes(), vec![0xf5, 0xf4, 0xf6]);
    }

    // ─── Decoder tests ───────────────────────────────────────────────────

    #[test]
    fn test_decode_unsigned_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_unsigned(42);
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_unsigned(100).unwrap(), 42);
        d.expect_eof().unwrap();
    }

    #[test]
    fn test_decode_string_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_text_string("hello");
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_text_string(100).unwrap(), "hello");
        d.expect_eof().unwrap();
    }

    #[test]
    fn test_decode_byte_string_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_byte_string(&[1, 2, 3]);
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_byte_string(100).unwrap(), &[1, 2, 3]);
        d.expect_eof().unwrap();
    }

    #[test]
    fn test_decode_array_roundtrip() {
        let mut e = CborEncoder::new();
        e.write_array_header(3);
        e.write_unsigned(10);
        e.write_unsigned(20);
        e.write_unsigned(30);
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_array_header(10).unwrap(), 3);
        assert_eq!(d.read_unsigned(100).unwrap(), 10);
        assert_eq!(d.read_unsigned(100).unwrap(), 20);
        assert_eq!(d.read_unsigned(100).unwrap(), 30);
        d.expect_eof().unwrap();
    }

    // ─── Non-canonical rejection ─────────────────────────────────────────

    #[test]
    fn test_reject_non_canonical_unsigned() {
        // 0 encoded as 0x1800 (two bytes instead of one)
        let mut d = CborDecoder::new(&[0x18, 0x00]);
        assert!(matches!(
            d.read_unsigned(100),
            Err(DecodeError::NonCanonicalEncoding { .. })
        ));
    }

    #[test]
    fn test_reject_truncated() {
        let mut d = CborDecoder::new(&[0x5A, 0x00]); // byte string header expecting 2 more bytes
        assert!(matches!(
            d.read_byte_string(100),
            Err(DecodeError::TruncatedCbor { .. })
        ));
    }

    #[test]
    fn test_reject_trailing_bytes() {
        let mut e = CborEncoder::new();
        e.write_unsigned(1);
        let mut data = e.into_bytes();
        data.push(0x00); // trailing
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_unsigned(100).unwrap(), 1);
        assert!(matches!(
            d.expect_eof(),
            Err(DecodeError::TrailingBytes { .. })
        ));
    }

    #[test]
    fn test_decode_bool() {
        let mut d = CborDecoder::new(&[0xf5]);
        assert_eq!(d.read_bool().unwrap(), true);
        let mut d = CborDecoder::new(&[0xf4]);
        assert_eq!(d.read_bool().unwrap(), false);
    }

    #[test]
    fn test_decode_null() {
        let mut d = CborDecoder::new(&[0xf6]);
        d.read_null().unwrap();
    }

    #[test]
    fn test_decode_map_then_keys() {
        let mut e = CborEncoder::new();
        e.write_map_header(2);
        e.write_unsigned(1);
        e.write_text_string("a");
        e.write_unsigned(2);
        e.write_text_string("b");
        let data = e.into_bytes();
        let mut d = CborDecoder::new(&data);
        assert_eq!(d.read_map_header(10).unwrap(), 2);
        assert_eq!(d.read_unsigned(10).unwrap(), 1);
        assert_eq!(d.read_text_string(10).unwrap(), "a");
        assert_eq!(d.read_unsigned(10).unwrap(), 2);
        assert_eq!(d.read_text_string(10).unwrap(), "b");
        d.expect_eof().unwrap();
    }
}
