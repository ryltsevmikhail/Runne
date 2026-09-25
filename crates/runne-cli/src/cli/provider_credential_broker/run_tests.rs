use std::io::{Cursor, Read};
use std::sync::{Arc, Mutex};

use runne_provider::{
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialOperationAction,
};

use super::effect_test_support::{EffectCall, assert_frames, claimed, pair_claimed_successfully};
use super::run::execute_claimed_writer;

#[test]
fn successful_broker_process_emits_no_receipt_or_diagnostic_text() {
    let outcome = super::broker_process_outcome(Ok(()));

    assert_eq!(outcome.exit_code, 0);
    assert!(outcome.stdout.is_empty());
    assert!(outcome.stderr.is_empty());
}

#[test]
#[cfg(target_os = "macos")]
fn packaged_runner_accepts_only_pinned_session_and_detected_secret_slot() {
    let runner: fn(
        runne_native_enrollment_authority::PendingPinnedProviderCredentialWriterSessionV1,
        super::channel::InheritedSecretInputSlot,
    ) -> Result<(), super::CliError> = super::run::run_authenticated_writer;
    let _ = runner;
}

#[test]
fn secret_is_read_only_after_claim() {
    let fixture = pair_claimed_successfully();
    let reader = ClaimCheckingReader {
        input: Cursor::new(encoded_pair_envelope()),
        written: fixture.written.clone(),
    };

    assert!(execute_claimed_writer(fixture.claimed, Some(reader)).is_ok());
    assert_eq!(
        *fixture.calls.lock().expect("calls"),
        vec![EffectCall::Create]
    );
    assert_frames(&fixture.written, true);
}

#[test]
fn non_pair_runner_executes_without_constructing_a_secret_reader() {
    let fixture = claimed(CredentialOperationAction::MigrateLegacy);

    assert!(execute_claimed_writer::<Cursor<Vec<u8>>>(fixture.claimed, None).is_ok());
    assert_eq!(
        *fixture.calls.lock().expect("calls"),
        vec![EffectCall::ImportLegacy]
    );
    assert_frames(&fixture.written, true);
}

struct ClaimCheckingReader {
    input: Cursor<Vec<u8>>,
    written: Arc<Mutex<Vec<u8>>>,
}

impl Read for ClaimCheckingReader {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        let written = self.written.lock().expect("written").clone();
        assert!(matches!(
            CredentialBrokerFrameCodec::read_from(&mut Cursor::new(written)),
            Ok(CredentialBrokerFrame::Claim { .. })
        ));
        self.input.read(bytes)
    }
}

fn encoded_pair_envelope() -> Vec<u8> {
    let command = super::effect_test_support::command(CredentialOperationAction::Pair);
    let mut bytes = vec![0; 141];
    bytes[..2].copy_from_slice(&[runne_provider::CredentialSecretEnvelopeCodec::VERSION, 2]);
    bytes[2..18].copy_from_slice(&command.operation_id().as_bytes());
    bytes[18..26].copy_from_slice(&command.ticket_attempt().get().to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}
