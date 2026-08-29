use std::io::Cursor;

use super::effect_test_support::{assert_frames, pair_claimed};

#[test]
fn pair_secret_source_rejects_invalid_input_before_native_effect() {
    for input in [
        b"secret\n".to_vec(),
        envelope_with_trailing_byte(),
        vec![0; runne_provider::CredentialSecretEnvelopeCodec::MAX_BYTES + 1],
    ] {
        let fixture = pair_claimed();

        assert!(fixture
            .claimed
            .read_pair_secret(&mut Cursor::new(input))
            .is_err());
        assert!(fixture.calls.lock().expect("calls").is_empty());
        assert_frames(&fixture.written, false);
    }
}

fn envelope_with_trailing_byte() -> Vec<u8> {
    let mut bytes = vec![0; 142];
    bytes[..2].copy_from_slice(&[
        runne_provider::CredentialSecretEnvelopeCodec::VERSION,
        2,
    ]);
    bytes[2..18].fill(21);
    bytes[18..26].copy_from_slice(&1_u64.to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}
