use std::io::{Cursor, Read, Write};

use sha2::{Digest as _, Sha256};

use crate::{
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialEnrollmentAuthorityPair,
    CredentialSecretInputPresence, CredentialWriterAuthorityPair, CredentialWriterCommandScopeV1,
    CredentialWriterQualifiedPreludeCodec, PendingCredentialIssueTicketV1,
    daemon_credential_publication,
};

use super::qualification_admission::{self, AdmissionMutation};
use super::qualification_release;
use super::support::{claims, current_claims, frame};

#[test]
fn invalid_receiver_admissions_emit_no_ack_or_authorization() {
    for mutation in [
        AdmissionMutation::BadContextKey,
        AdmissionMutation::BadFaultKey,
        AdmissionMutation::Expired,
        AdmissionMutation::WrongRole,
        AdmissionMutation::CandidateMismatch,
        AdmissionMutation::TupleMismatch,
    ] {
        reject_after_claim(mutation, true);
    }
    reject_after_claim(AdmissionMutation::Valid, false);
}

#[test]
fn v2_only_release_cannot_initialize_the_receiver() {
    let issue = frame(91, 1, 92, 4, 93, 1);
    let attested_claims = current_claims(&issue);
    let pending = PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(
        CredentialBrokerFrameCodec::encode(issue).unwrap(),
    ))
    .unwrap();
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([4; 32])
            .unwrap();
    let (attestation, _) = signer
        .sign_qualified(attested_claims, 99, [1; 32], [2; 32])
        .unwrap();
    let (_, verifier) =
        qualification_admission::signed_writer_admission(unix_seconds(), [1; 32], [2; 32]);
    assert!(
        pending
            .with_qualified_attestation(attestation)
            .bind_test_verified_qualification_release(
                &qualification_release::verified_v2_release(),
                verifier,
            )
            .is_err()
    );
}

#[test]
fn expired_attestation_is_rejected_before_claim_or_ack() {
    let issue = frame(96, 1, 97, 4, 98, 1);
    let attested_claims = claims(&issue);
    let pending = PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(
        CredentialBrokerFrameCodec::encode(issue).unwrap(),
    ))
    .unwrap();
    let (attestation, _) =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([4; 32])
            .unwrap()
            .sign_qualified(attested_claims, 99, [1; 32], [2; 32])
            .unwrap();
    let mut control = ScriptedControl::new(Vec::new());
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([4; 32]).unwrap();
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    assert!(
        pending
            .with_qualified_attestation(attestation)
            .claim_on(
                &mut control,
                &issuer,
                &channel,
                CredentialSecretInputPresence::Present,
                CredentialWriterCommandScopeV1::D1_1A,
            )
            .is_err()
    );
    assert!(control.written.is_empty());
}

fn reject_after_claim(mutation: AdmissionMutation, bind_release: bool) {
    let issue = frame(101, 1, 102, 4, 103, 1);
    let attested_claims = current_claims(&issue);
    let (operation_id, attempt) = match &issue {
        CredentialBrokerFrame::IssueTicket {
            operation_id,
            attempt,
            ..
        } => (*operation_id, *attempt),
        _ => unreachable!(),
    };
    let pending = PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(
        CredentialBrokerFrameCodec::encode(issue).unwrap(),
    ))
    .unwrap();
    let release = qualification_release::verified_release();
    let tuple = release.native_enrollment_tuple_v3().unwrap();
    let (bundle, verifier) = qualification_admission::signed_writer_admission_case(
        unix_seconds(),
        tuple.candidate_digest(),
        tuple.tuple_digest(),
        mutation,
    );
    let (context_digest, ticket_digest) = member_digests(&bundle);
    let (attestation, prelude_signer) =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([4; 32])
            .unwrap()
            .sign_qualified(attested_claims, 99, context_digest, ticket_digest)
            .unwrap();
    let (prelude, _) = prelude_signer.sign_prelude(bundle).unwrap();
    let accepted = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
        operation_id,
        attempt,
    })
    .unwrap();
    let mut control = ScriptedControl::new(
        [
            CredentialWriterQualifiedPreludeCodec::encode(&prelude).unwrap(),
            accepted,
        ]
        .concat(),
    );
    let pending = pending.with_qualified_attestation(attestation);
    let pending = if bind_release {
        pending
            .bind_test_verified_qualification_release(&release, verifier)
            .unwrap()
    } else {
        pending
    };
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([4; 32]).unwrap();
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    assert!(
        pending
            .claim_on(
                &mut control,
                &issuer,
                &channel,
                CredentialSecretInputPresence::Present,
                CredentialWriterCommandScopeV1::D1_1A,
            )
            .is_err(),
        "receiver accepted {mutation:?}"
    );
    let mut written = Cursor::new(control.written);
    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut written),
        Ok(CredentialBrokerFrame::Claim { .. })
    ));
    assert_eq!(written.position() as usize, written.get_ref().len());
}

struct ScriptedControl {
    readable: Cursor<Vec<u8>>,
    written: Vec<u8>,
}

impl ScriptedControl {
    fn new(readable: Vec<u8>) -> Self {
        Self {
            readable: Cursor::new(readable),
            written: Vec::new(),
        }
    }
}

impl Read for ScriptedControl {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.readable.read(bytes)
    }
}

impl Write for ScriptedControl {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn member_digests(bundle: &[u8]) -> ([u8; 32], [u8; 32]) {
    let context_len = u32::from_be_bytes(bundle[9..13].try_into().unwrap()) as usize;
    let context_end = 17 + context_len;
    (
        Sha256::digest(&bundle[17..context_end]).into(),
        Sha256::digest(&bundle[context_end..]).into(),
    )
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
