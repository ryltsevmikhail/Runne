use std::io::Cursor;

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialOperationId, CredentialTicketAttempt,
};

use super::effect::execute_pair_effect;
use super::effect_test_support::{
    assert_frames, pair_claimed, pair_claimed_successfully, pair_claimed_with_release,
};

#[test]
fn pair_secret_source_rejects_invalid_input_before_native_effect() {
    for input in [
        b"secret\n".to_vec(),
        envelope_with_trailing_byte(),
        vec![0; runne_provider::CredentialSecretEnvelopeCodec::MAX_BYTES + 1],
    ] {
        let fixture = pair_claimed();

        assert!(
            fixture
                .claimed
                .read_pair_secret(&mut Cursor::new(input))
                .is_err()
        );
        assert!(fixture.calls.lock().expect("calls").is_empty());
        assert_frames(&fixture.written, false);
    }
}

#[test]
fn pair_effect_requires_the_exact_post_ack_release() {
    for release in [
        None,
        Some(release([22; 16], 1, [13; 32])),
        Some(release([21; 16], 2, [13; 32])),
        Some(release([21; 16], 1, [14; 32])),
    ] {
        let fixture = pair_claimed_with_release(release);
        assert!(
            fixture
                .claimed
                .read_pair_secret(&mut Cursor::new(valid_envelope()))
                .is_err()
        );
        assert!(fixture.calls.lock().expect("calls").is_empty());
        assert_frames(&fixture.written, false);
    }

    let fixture = pair_claimed_successfully();
    let authority = fixture
        .claimed
        .read_pair_secret(&mut Cursor::new(valid_envelope()))
        .expect("exact release");
    assert!(fixture.calls.lock().expect("calls").is_empty());
    assert!(execute_pair_effect(authority).is_ok());
    assert_eq!(fixture.calls.lock().expect("calls").len(), 1);
    assert_frames(&fixture.written, true);
}

fn release(operation: [u8; 16], attempt: u64, binding: [u8; 32]) -> CredentialBrokerFrame {
    CredentialBrokerFrame::NativeEffectRelease {
        operation_id: CredentialOperationId::from_bytes(operation).expect("operation"),
        attempt: CredentialTicketAttempt::new(attempt).expect("attempt"),
        binding: CredentialBindingDigest::from_measured(binding).expect("binding"),
    }
}

fn valid_envelope() -> Vec<u8> {
    let mut bytes = vec![0; 141];
    bytes[..2].copy_from_slice(&[runne_provider::CredentialSecretEnvelopeCodec::VERSION, 2]);
    bytes[2..18].fill(21);
    bytes[18..26].copy_from_slice(&1_u64.to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}

fn envelope_with_trailing_byte() -> Vec<u8> {
    let mut bytes = vec![0; 142];
    bytes[..2].copy_from_slice(&[runne_provider::CredentialSecretEnvelopeCodec::VERSION, 2]);
    bytes[2..18].fill(21);
    bytes[18..26].copy_from_slice(&1_u64.to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}
