//! Exact bounded response only; successful bytes do not prove close/Child facts.
pub(super) const INPUT_CAP: usize = 2046;
pub(super) fn decode(frame: &[u8], input: usize) -> Result<(), &'static str> {
    if !(1..=INPUT_CAP).contains(&input) || frame.len() > 160 {
        return Err("final collection input/header cap");
    }
    let expected = format!("R05_COLLECTION_HELPER_V1 bytes={input} closed=4\n");
    if frame != expected.as_bytes() {
        return Err("exact final collection frame/count/closes");
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_four_close_response_cannot_accept_case_helper_or_trailing_bytes() {
        assert!(decode(b"R05_COLLECTION_HELPER_V1 bytes=2 closed=4\n", 2).is_ok());
        for text in [
            "R05_COLLECTION_HELPER_V1 bytes=02 closed=4\n",
            "R05_COLLECTION_HELPER_V1 bytes=2 closed=3\n",
            "R05_COLLECTION_HELPER_V1 bytes=2 closed=4\n{}",
            "R05_COLLECTION_HELPER_V1 bytes=2 closed=4\n\n",
            "R05_RECORD_HELPER_V1 op=publish name=running-cut bytes=2 closed=3\n",
        ] {
            assert!(decode(text.as_bytes(), 2).is_err());
        }
        assert!(decode(b"R05_COLLECTION_HELPER_V1 bytes=2 closed=4\n", 3).is_err());
        assert!(decode(b"", 0).is_err());
        assert!(decode(b"", INPUT_CAP + 1).is_err());
        assert!(decode(&vec![b'x'; 161], 2).is_err());
    }
}
