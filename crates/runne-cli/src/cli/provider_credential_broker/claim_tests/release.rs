use std::io::Cursor;
use std::sync::Arc;

use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialOperationAction, CredentialOperationId, CredentialSecretInputPresence,
    CredentialTicketAttempt,
};

use super::*;

#[test]
fn non_pair_claim_requires_an_exact_release_before_authorizing_effect() {
    for mismatch in [0, 1, 2, 3] {
        let command = command(14 + mismatch, CredentialOperationAction::Revoke);
        let release = (mismatch != 0).then(|| CredentialBrokerFrame::NativeEffectRelease {
            operation_id: if mismatch == 1 {
                CredentialOperationId::from_bytes([99; 16]).unwrap()
            } else {
                command.operation_id()
            },
            attempt: CredentialTicketAttempt::new(if mismatch == 2 { 2 } else { 1 }).unwrap(),
            binding: if mismatch == 3 {
                CredentialBindingDigest::from_measured([99; 32]).unwrap()
            } else {
                binding()
            },
        });
        let (parts, written) = endpoint(&command, release);
        let claimed = claim_for_test(parts, CredentialSecretInputPresence::Absent)
            .expect("exact claim acknowledgement");
        assert!(claimed.authorize_without_secret().is_err());
        assert_one_claim(&written, false);
    }
}

#[test]
fn non_pair_claim_authorizes_without_a_secret_offer() {
    let command = command(7, CredentialOperationAction::Revoke);
    let (parts, written) = endpoint(&command, Some(exact_release(&command)));
    let claimed = claim_for_test(parts, CredentialSecretInputPresence::Absent)
        .expect("exact acknowledgement");
    let authorized = claimed.authorize_without_secret().expect("non-pair effect");
    assert_eq!(authorized.command_for_test(), &command);
    assert_eq!(Arc::strong_count(&written), 2, "control remains retained");
    drop(authorized);
    assert_eq!(
        Arc::strong_count(&written),
        1,
        "control closes with authority"
    );
    assert_one_claim(&written, false);
}

fn endpoint(
    command: &runne_provider::CredentialBrokerCommand,
    release: Option<CredentialBrokerFrame>,
) -> (TestClaimParts, Arc<std::sync::Mutex<Vec<u8>>>) {
    let (mut parts, written) = super::endpoint(
        super::issue(command.clone(), binding(), [11; 32]),
        Some(super::accepted(command)),
    );
    let mut incoming = Vec::new();
    CredentialBrokerFrameCodec::write_to(&mut incoming, super::accepted(command)).unwrap();
    if let Some(release) = release {
        CredentialBrokerFrameCodec::write_to(&mut incoming, release).unwrap();
    }
    parts.control.input = Cursor::new(incoming);
    (parts, written)
}

fn exact_release(command: &runne_provider::CredentialBrokerCommand) -> CredentialBrokerFrame {
    CredentialBrokerFrame::NativeEffectRelease {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
        binding: binding(),
    }
}
