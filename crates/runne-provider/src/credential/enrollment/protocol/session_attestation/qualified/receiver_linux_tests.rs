use std::io::Cursor;

use crate::daemon_credential_publication::CredentialWriterSessionAttestationSigner;
use crate::*;

use super::bind_verified_linux_attestation;

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn issue() -> CredentialBrokerFrame {
    let provider = ProviderId::new("deepseek").unwrap();
    let operation = CredentialOperationId::from_bytes([1; 16]).unwrap();
    let attempt = CredentialTicketAttempt::new(1).unwrap();
    let command = CredentialBrokerCommand::new(
        operation,
        attempt,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialBrokerTarget::Version(CredentialVersionRef::new(provider, 1).unwrap()),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        None,
    )
    .unwrap();
    CredentialBrokerFrame::IssueTicket {
        operation_id: operation,
        attempt,
        ticket: RawCredentialTicket::generate().unwrap(),
        channel_binding: [4; 32],
        binding: digest(3),
        command,
    }
}

fn signed(issue: &CredentialBrokerFrame) -> (Vec<u8>, [u8; 32]) {
    let CredentialBrokerFrame::IssueTicket {
        operation_id,
        attempt,
        ..
    } = issue
    else {
        unreachable!()
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = CredentialWriterSessionAttestationClaimsV1::new(
        CredentialWriterSessionTicketClaimsV1::new(
            *operation_id,
            *attempt,
            CredentialIssueTicketBindingV1::from_issue_ticket(issue).unwrap(),
            digest(3),
            CredentialInstallationOwnerId::from_bytes([5; 32]).unwrap(),
            digest(6),
            now - 30,
            now + 600,
        )
        .unwrap(),
        CredentialWriterSessionRuntimeClaimsV1::new(
            digest(7),
            digest(8),
            digest(9),
            1,
            1,
            digest(12),
        )
        .unwrap(),
        CredentialWriterSessionProcessClaimsV1::new(
            digest(16),
            digest(17),
            digest(18),
            digest(19),
            digest(20),
            digest(21),
        )
        .unwrap(),
    );
    let signer = CredentialWriterSessionAttestationSigner::generate([4; 32]).unwrap();
    let key = signer.public_key();
    let (attestation, _) = signer
        .sign_qualified(claims, 1, [31; 32], [32; 32])
        .unwrap();
    (
        CredentialWriterSessionAttestationV2Codec::encode(&attestation).to_vec(),
        key,
    )
}

fn pending(issue: CredentialBrokerFrame) -> PendingCredentialIssueTicketV1 {
    PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(
        CredentialBrokerFrameCodec::encode(issue).unwrap(),
    ))
    .unwrap()
}

#[test]
fn signed_linux_control_requires_prelude_even_for_fresh_wire_ticket() {
    let issue = issue();
    let (bytes, key) = signed(&issue);
    let ticket = bind_verified_linux_attestation(pending(issue), &bytes, key, [12; 32]).unwrap();
    assert!(
        ticket.is_qualified(),
        "signed V2 control must not downgrade to an ordinary claim"
    );
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([4; 32]).unwrap();
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    // An ordinary ClaimAccepted response cannot substitute for the signed
    // qualification prelude. No native effect authority may be returned.
    let accepted = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
        operation_id: CredentialOperationId::from_bytes([1; 16]).unwrap(),
        attempt: CredentialTicketAttempt::new(1).unwrap(),
    })
    .unwrap();
    let mut control = Control {
        input: Cursor::new(accepted.to_vec()),
        output: Vec::new(),
    };
    assert!(
        ticket
            .claim_on(
                &mut control,
                &issuer,
                &channel,
                CredentialSecretInputPresence::Present,
                CredentialWriterCommandScopeV1::D1_1A,
            )
            .is_err()
    );
    let mut written = control.output.as_slice();
    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut written).unwrap(),
        CredentialBrokerFrame::Claim { .. }
    ));
    assert!(
        written.is_empty(),
        "no qualification ACK after an ordinary reply"
    );
}

#[test]
fn linux_control_rejects_a_different_ticket_under_the_same_release() {
    let first = issue();
    let (bytes, key) = signed(&first);
    assert!(bind_verified_linux_attestation(pending(issue()), &bytes, key, [12; 32]).is_err());
}

struct Control {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
}

impl std::io::Read for Control {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(&mut self.input, bytes)
    }
}

impl std::io::Write for Control {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
