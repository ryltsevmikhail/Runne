use std::io::{Cursor, Read, Write};

use sha2::{Digest as _, Sha256};

use crate::{
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialEnrollmentAuthorityPair,
    CredentialSecretInputPresence, CredentialWriterAuthorityPair, CredentialWriterCommandScopeV1,
    CredentialWriterQualifiedAckCodec, CredentialWriterQualifiedPreludeCodec,
    CredentialWriterSessionAttestationV2Codec, PendingCredentialIssueTicketV1,
    daemon_credential_publication,
};

use super::support::{claims, current_claims, frame};

#[test]
fn qualified_records_have_exact_sizes_and_transitive_digests() {
    let issue = frame(51, 1, 52, 53, 54, 1);
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([53; 32])
            .unwrap();
    let public_key = signer.public_key();
    let (attestation, pending) = signer
        .sign_qualified(claims(&issue), 77, [55; 32], [56; 32])
        .unwrap();
    let attestation_bytes = CredentialWriterSessionAttestationV2Codec::encode(&attestation);
    assert_eq!(attestation_bytes.len(), 715);
    let decoded = CredentialWriterSessionAttestationV2Codec::decode_and_verify(
        &attestation_bytes,
        public_key,
    )
    .unwrap();
    assert_eq!(
        CredentialWriterSessionAttestationV2Codec::full_digest(&decoded),
        CredentialWriterSessionAttestationV2Codec::full_digest(&attestation)
    );

    let (prelude, awaiting_ack) = pending.sign_prelude(admission_bundle()).unwrap();
    let prelude_bytes = CredentialWriterQualifiedPreludeCodec::encode(&prelude).unwrap();
    assert_eq!(prelude_bytes.len(), 117 + 32);
    let prelude =
        CredentialWriterQualifiedPreludeCodec::decode_and_verify(&prelude_bytes, public_key)
            .unwrap();
    let ack = awaiting_ack.expected_ack(&prelude);
    let ack_bytes = CredentialWriterQualifiedAckCodec::encode(&ack);
    assert_eq!(ack_bytes.len(), 81);
    let decoded_ack = CredentialWriterQualifiedAckCodec::decode(&ack_bytes).unwrap();
    let _publication = awaiting_ack.accept_ack(decoded_ack).unwrap();
    assert!(CredentialWriterQualifiedAckCodec::decode(&ack_bytes).is_ok());
}

#[test]
fn qualified_decoders_reject_wrong_versions_and_truncation() {
    let issue = frame(61, 1, 62, 63, 64, 1);
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([63; 32])
            .unwrap();
    let public_key = signer.public_key();
    let (attestation, _) = signer
        .sign_qualified(claims(&issue), 88, [65; 32], [66; 32])
        .unwrap();
    let mut bytes = CredentialWriterSessionAttestationV2Codec::encode(&attestation);
    bytes[0] = 3;
    assert!(
        CredentialWriterSessionAttestationV2Codec::decode_and_verify(&bytes, public_key).is_err()
    );
    let mut cursor = Cursor::new(bytes);
    assert!(CredentialWriterSessionAttestationV2Codec::read_from(&mut cursor, public_key).is_err());

    let (attestation, pending) =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([63; 32])
            .unwrap()
            .sign_qualified(claims(&issue), 88, [65; 32], [66; 32])
            .unwrap();
    let _ = attestation;
    let (prelude, _) = pending.sign_prelude(admission_bundle()).unwrap();
    let mut prelude_bytes = CredentialWriterQualifiedPreludeCodec::encode(&prelude).unwrap();
    prelude_bytes[8] = 2;
    assert!(
        CredentialWriterQualifiedPreludeCodec::decode_and_verify(&prelude_bytes, [63; 32]).is_err()
    );
    assert!(
        CredentialWriterQualifiedPreludeCodec::decode_and_verify(
            &prelude_bytes[..prelude_bytes.len() - 1],
            [63; 32]
        )
        .is_err()
    );
}

#[test]
fn qualified_claim_exchange_reads_prelude_before_claim_accepted() {
    let issue = frame(71, 1, 72, 4, 73, 1);
    let attested_claims = current_claims(&issue);
    let (operation_id, attempt) = match &issue {
        CredentialBrokerFrame::IssueTicket {
            operation_id,
            attempt,
            ..
        } => (*operation_id, *attempt),
        _ => unreachable!(),
    };
    let encoded_issue = CredentialBrokerFrameCodec::encode(issue).unwrap();
    let pending =
        PendingCredentialIssueTicketV1::read_from(&mut Cursor::new(encoded_issue)).unwrap();
    let now = unix_seconds();
    let release = super::qualification_release::verified_release();
    let tuple = release.native_enrollment_tuple_v3().unwrap();
    let (bundle, verifier) = super::qualification_admission::signed_writer_admission(
        now,
        tuple.candidate_digest(),
        tuple.tuple_digest(),
    );
    let (context_sha256, ticket_sha256) = member_digests(&bundle);
    let signer =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([4; 32])
            .unwrap();
    let (attestation, prelude_signer) = signer
        .sign_qualified(attested_claims, 99, context_sha256, ticket_sha256)
        .unwrap();
    let (prelude, ack_signer) = prelude_signer.sign_prelude(bundle).unwrap();
    let prelude_bytes = CredentialWriterQualifiedPreludeCodec::encode(&prelude).unwrap();
    let accepted = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::ClaimAccepted {
        operation_id,
        attempt,
    })
    .unwrap();
    let mut control = ScriptedControl::new([prelude_bytes, accepted].concat());
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let channel = measurements.broker_channel_binding([4; 32]).unwrap();
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();

    let (authorization, ..) = pending
        .with_qualified_attestation(attestation)
        .bind_test_verified_qualification_release(&release, verifier)
        .unwrap()
        .claim_on(
            &mut control,
            &issuer,
            &channel,
            CredentialSecretInputPresence::Present,
            CredentialWriterCommandScopeV1::D1_1A,
        )
        .unwrap();
    assert!(authorization.test_only_has_writer_fault());

    let mut written = Cursor::new(control.written);
    assert!(matches!(
        CredentialBrokerFrameCodec::read_from(&mut written),
        Ok(CredentialBrokerFrame::Claim { .. })
    ));
    let mut ack_bytes = [0; 81];
    written.read_exact(&mut ack_bytes).unwrap();
    let ack = CredentialWriterQualifiedAckCodec::decode(&ack_bytes).unwrap();
    assert_eq!(
        CredentialWriterQualifiedAckCodec::encode(&ack),
        CredentialWriterQualifiedAckCodec::encode(&ack_signer.expected_ack(&prelude))
    );
}

#[test]
fn qualified_claim_rejects_shape_only_admission_without_ack() {
    let issue = frame(81, 1, 82, 4, 83, 1);
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
    let bundle = admission_bundle();
    let context_sha256: [u8; 32] = Sha256::digest(&bundle[17..27]).into();
    let ticket_sha256: [u8; 32] = Sha256::digest(&bundle[27..32]).into();
    let (attestation, prelude_signer) =
        daemon_credential_publication::CredentialWriterSessionAttestationSigner::generate([4; 32])
            .unwrap()
            .sign_qualified(attested_claims, 99, context_sha256, ticket_sha256)
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
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.readable.read(buffer)
    }
}

impl Write for ScriptedControl {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.written.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn admission_bundle() -> Vec<u8> {
    let mut bundle = b"RNQADM1\0".to_vec();
    bundle.push(1);
    bundle.extend_from_slice(&10_u32.to_be_bytes());
    bundle.extend_from_slice(&5_u32.to_be_bytes());
    bundle.extend_from_slice(&[0xab; 10]);
    bundle.extend_from_slice(&[0xcd; 5]);
    bundle
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
