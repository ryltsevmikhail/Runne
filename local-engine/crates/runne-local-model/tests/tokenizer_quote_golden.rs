//! Tokenizer quote golden/determinism (Plan Task 21 Step 2): same
//! bytes + same pinned revision → identical quote; unregistered
//! revisions refuse instead of estimating; registered vectors are
//! golden.

use runne_local_model::tokenizer_quote::{
    QuoteError, QuoteRevision, revision_from_name, token_quote,
};

const GOLDEN_BYTES: &[u8] = b"hello, tokenizer world! 123";

#[test]
fn same_bytes_same_revision_identical_quote() {
    let a = token_quote(QuoteRevision::IdentityBytesV1, GOLDEN_BYTES).expect("q1");
    let b = token_quote(QuoteRevision::IdentityBytesV1, GOLDEN_BYTES).expect("q2");
    assert_eq!(a, b);
    let a = token_quote(QuoteRevision::Utf8CharsV1, GOLDEN_BYTES).expect("q3");
    let b = token_quote(QuoteRevision::Utf8CharsV1, GOLDEN_BYTES).expect("q4");
    assert_eq!(a, b);
}

#[test]
fn golden_vectors() {
    // 27 ASCII bytes → 27 byte-tokens.
    assert_eq!(GOLDEN_BYTES.len(), 27);
    assert_eq!(
        token_quote(QuoteRevision::IdentityBytesV1, GOLDEN_BYTES).expect("bytes"),
        27
    );
    // 24 chars (space and punctuation count as chars, no surrogates).
    assert_eq!(
        token_quote(QuoteRevision::Utf8CharsV1, GOLDEN_BYTES).expect("chars"),
        24 + 3,
        "three word-spaces included in the char count"
    );
    // Multi-byte char: 2 bytes but 1 char — the revisions diverge
    // deterministically.
    let mb = "ё".as_bytes();
    assert_eq!(mb.len(), 2);
    assert_eq!(
        token_quote(QuoteRevision::IdentityBytesV1, mb).expect("bytes"),
        2
    );
    assert_eq!(
        token_quote(QuoteRevision::Utf8CharsV1, mb).expect("chars"),
        1
    );
}

#[test]
fn unregistered_revision_refuses_never_estimates() {
    assert_eq!(
        revision_from_name("char/4"),
        Err(QuoteError::UnknownRevision("char/4".into()))
    );
    let parsed = revision_from_name("identity-bytes-v1").expect("registered");
    assert_eq!(parsed, QuoteRevision::IdentityBytesV1);
}

#[test]
fn invalid_utf8_refuses_char_revision() {
    let broken: &[u8] = &[0xFF, 0xFE];
    assert_eq!(
        token_quote(QuoteRevision::Utf8CharsV1, broken),
        Err(QuoteError::InvalidUtf8)
    );
    // The byte revision is total.
    assert_eq!(
        token_quote(QuoteRevision::IdentityBytesV1, broken).expect("bytes"),
        2
    );
}
