use gocode_pairing_crypto::{
    BootstrapTranscriptError, BootstrapTranscriptV3, encode_final_transcript,
    encode_preallocation_transcript,
};

fn fixture(server_nonce_slot: &[u8]) -> BootstrapTranscriptV3<'_> {
    BootstrapTranscriptV3 {
        key_version: 1,
        fields: [
            &b"v3"[..],
            &b"\x01"[..],
            &b"p"[..],
            &b"\x02\x03"[..],
            &b"profile"[..],
            &b"\x04"[..],
            &b"\x05"[..],
            &b"\x06"[..],
            &b"\x07"[..],
            &b"\x08"[..],
            &b"/e"[..],
            &b"POST"[..],
            &b"n"[..],
            &b"x"[..],
            &b"\x09\x0a"[..],
            server_nonce_slot,
        ],
    }
}

#[test]
fn golden_preallocation_and_final_transcripts_are_prefix_free() {
    let expected_preallocation = hex::decode(concat!(
        "474f434f44455f424f4f54535452415000", // GOCODE_BOOTSTRAP\0
        "0001",                               // key version
        "000000027633",
        "0000000101",
        "0000000170",
        "000000020203",
        "0000000770726f66696c65",
        "0000000104",
        "0000000105",
        "0000000106",
        "0000000107",
        "0000000108",
        "000000022f65",
        "00000004504f5354",
        "000000016e",
        "0000000178",
        "00000002090a",
        "00000000",
    ))
    .unwrap();
    let expected_final = hex::decode(concat!(
        "474f434f44455f424f4f54535452415000",
        "0001",
        "000000027633",
        "0000000101",
        "0000000170",
        "000000020203",
        "0000000770726f66696c65",
        "0000000104",
        "0000000105",
        "0000000106",
        "0000000107",
        "0000000108",
        "000000022f65",
        "00000004504f5354",
        "000000016e",
        "0000000178",
        "00000002090a",
        "00000020",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    ))
    .unwrap();

    let preallocation = encode_preallocation_transcript(&fixture(b"")).unwrap();
    let final_transcript = encode_final_transcript(&fixture(b""), [0x0b; 32]).unwrap();

    assert_eq!(preallocation, expected_preallocation);
    assert_eq!(final_transcript, expected_final);
    assert!(!preallocation.starts_with(&final_transcript));
    assert!(!final_transcript.starts_with(&preallocation));
}

#[test]
fn non_empty_reserved_server_nonce_slot_is_rejected() {
    assert_eq!(
        encode_preallocation_transcript(&fixture(b"caller supplied")),
        Err(BootstrapTranscriptError::NonEmptyServerNonceSlot),
    );
    assert_eq!(
        encode_final_transcript(&fixture(b"caller supplied"), [7; 32]),
        Err(BootstrapTranscriptError::NonEmptyServerNonceSlot),
    );
}
