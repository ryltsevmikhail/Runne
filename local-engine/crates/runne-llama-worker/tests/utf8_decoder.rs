//! Model-free characterization of the streaming API used by token_to_piece.
//! Generous buffers are intentional except in explicit capacity tests: upstream
//! llama-cpp-2 ignores OutputFull/consumed and may lose text with piece-sized
//! capacity. These tests do not qualify tokenizer inference or fix that consumer.
#![cfg(feature = "backend-llama-cpp")]

use encoding_rs::{CoderResult, Decoder, UTF_8};
use llama_cpp_2::{model::LlamaModel, token::LlamaToken, TokenToStringError};
use std::num::NonZeroU16;

#[test]
fn real_consumer_api_binding_without_model() {
    let _api: fn(&LlamaModel, LlamaToken, &mut Decoder, bool, Option<NonZeroU16>)
        -> Result<String, TokenToStringError> = LlamaModel::token_to_piece;
}

fn piece(decoder: &mut Decoder, bytes: &[u8], last: bool) -> (String, bool) {
    let mut out = String::with_capacity(bytes.len() * 3 + 16);
    let capacity = out.capacity();
    let (result, consumed, errors) = decoder.decode_to_string(bytes, &mut out, last);
    assert_eq!(result, CoderResult::InputEmpty);
    assert_eq!(consumed, bytes.len());
    assert_eq!(out.capacity(), capacity);
    (out, errors)
}

#[test]
fn every_scalar_split_retains_state_across_pieces() {
    for scalar in ["¢", "€", "😀"] {
        for split in 1..scalar.len() {
            let mut decoder = UTF_8.new_decoder();
            assert_eq!(piece(&mut decoder, &scalar.as_bytes()[..split], false), ("".into(), false));
            assert_eq!(piece(&mut decoder, &scalar.as_bytes()[split..], false), (scalar.into(), false));
            assert_eq!(piece(&mut decoder, b"!", true), ("!".into(), false));
        }
    }
    let mut decoder = UTF_8.new_decoder();
    let mut text = String::new();
    for byte in "a¢€😀z".as_bytes() {
        let (out, errors) = piece(&mut decoder, &[*byte], false);
        assert!(!errors);
        text.push_str(&out);
    }
    text.push_str(&piece(&mut decoder, b"", true).0);
    assert_eq!(text, "a¢€😀z");
}

#[test]
fn long_mixed_text_crosses_simd_and_scalar_boundaries() {
    let text = "abcdefghijklmnop¢€😀qrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ¢€😀abcdefghijklmnop";
    assert!(text.len() > 64);
    for split in 0..=text.len() {
        let mut decoder = UTF_8.new_decoder();
        let (mut out, first_error) = piece(&mut decoder, &text.as_bytes()[..split], false);
        let (tail, last_error) = piece(&mut decoder, &text.as_bytes()[split..], true);
        out.push_str(&tail);
        assert_eq!(out, text, "split={split}");
        assert!(!first_error && !last_error);
    }
    // Explicitly cross 16/32/64-byte boundaries with invalid input too.
    let mut bytes = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB".to_vec();
    bytes.extend_from_slice(b"\xff\xe2\x82\xac\xf0\x9f\x98\x80end");
    let expected = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789AB�€😀end";
    for split in [15, 16, 17, 31, 32, 33, 63, 64, 65, 66, 67] {
        let mut decoder = UTF_8.new_decoder();
        let (mut out, a) = piece(&mut decoder, &bytes[..split], false);
        let (tail, b) = piece(&mut decoder, &bytes[split..], true);
        out.push_str(&tail);
        assert_eq!(out, expected, "split={split}");
        assert!(a || b);
    }
}

#[test]
fn invalid_sequences_replace_with_explicit_error_flags() {
    for (bytes, expected) in [
        (&b"\xff"[..], "�"),
        (&b"\x80"[..], "�"),
        (&b"\xc0\xaf"[..], "��"),
        (&b"\xed\xa0\x80"[..], "���"),
        (&b"\xf4\x90\x80\x80"[..], "����"),
        (&b"\xe2(\xa1"[..], "�(�"),
    ] {
        for split in 0..=bytes.len() {
            let mut decoder = UTF_8.new_decoder();
            let (mut out, a) = piece(&mut decoder, &bytes[..split], false);
            let (tail, b) = piece(&mut decoder, &bytes[split..], true);
            out.push_str(&tail);
            assert_eq!(out, expected);
            assert!(a || b);
        }
    }
}

#[test]
fn incomplete_tail_is_pending_until_final_flush() {
    for bytes in [&b"\xc2"[..], &b"\xe2\x82"[..], &b"\xf0\x9f\x98"[..]] {
        let mut decoder = UTF_8.new_decoder();
        assert_eq!(piece(&mut decoder, bytes, false), ("".into(), false));
        assert_eq!(piece(&mut decoder, b"", false), ("".into(), false));
        assert_eq!(piece(&mut decoder, b"", true), ("�".into(), true));
    }
}

#[test]
fn output_full_consumed_count_and_retry_preserve_input() {
    for capacity in 0..=4 {
        let mut decoder = UTF_8.new_decoder();
        let mut out = String::with_capacity(capacity);
        assert_eq!(out.capacity(), capacity);
        let (result, consumed, errors) = decoder.decode_to_string(b"ABCDE", &mut out, false);
        assert_eq!(result, CoderResult::OutputFull);
        assert_eq!(consumed, capacity);
        assert_eq!(out.as_bytes(), &b"ABCDE"[..capacity]);
        assert!(!errors);
        assert_eq!(out.capacity(), capacity);
        out.reserve(16);
        let (result, read, errors) = decoder.decode_to_string(&b"ABCDE"[consumed..], &mut out, true);
        assert_eq!((result, read, errors), (CoderResult::InputEmpty, 5 - consumed, false));
        assert_eq!(out, "ABCDE");
    }
}

#[test]
fn tiny_continuation_capacity_requires_retry_not_consumer_success() {
    let mut decoder = UTF_8.new_decoder();
    assert_eq!(piece(&mut decoder, b"\xf0\x9f\x98", false), ("".into(), false));
    let mut out = String::with_capacity(1); // llama's current-piece-sized allocation
    assert_eq!(out.capacity(), 1);
    let result = decoder.decode_to_string(b"\x80", &mut out, false);
    assert_eq!(result, (CoderResult::OutputFull, 0, false));
    assert_eq!(out, "");
    out.reserve(16);
    assert_eq!(decoder.decode_to_string(b"\x80", &mut out, true), (CoderResult::InputEmpty, 1, false));
    assert_eq!(out, "😀");
    // Replacement needs three output bytes despite only one input byte.
    let mut decoder = UTF_8.new_decoder();
    let mut out = String::with_capacity(1);
    assert_eq!(decoder.decode_to_string(b"\xff", &mut out, false), (CoderResult::OutputFull, 0, false));
    out.reserve(16);
    assert_eq!(decoder.decode_to_string(b"\xff", &mut out, true), (CoderResult::InputEmpty, 1, true));
    assert_eq!(out, "�");
}
