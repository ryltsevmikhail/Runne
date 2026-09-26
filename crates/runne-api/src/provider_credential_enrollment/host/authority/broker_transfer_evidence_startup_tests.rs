use super::*;
use crate::{
    CredentialBrokerTransferAuthenticator, CredentialBrokerWriterStartupAuthenticator, LaunchSecret,
};

fn make_authority(
    authenticator: CredentialBrokerTransferAuthenticator,
) -> ProviderCredentialBrokerTransferAuthority {
    ProviderCredentialBrokerTransferAuthority {
        seal: Arc::new(AuthoritySeal),
        transfer_seal: Arc::new(AuthoritySeal),
        protected_session_binding: [9; 32],
        authenticator,
        writer_evidence_available: true,
    }
}

fn signed_frame(startup: &CredentialBrokerWriterStartupAuthenticator) -> ([u8; 256], [u8; 32]) {
    let mut record = [0; 256];
    record[..32].copy_from_slice(&startup.channel());
    record[32..64].copy_from_slice(&startup.publication_key());
    record[64..96].copy_from_slice(&startup.nonce());
    record[128..160].copy_from_slice(&[3; 32]);
    record[160..192].copy_from_slice(&[4; 32]);
    record[192..224].copy_from_slice(&startup.release());
    record[224..].copy_from_slice(&[5; 32]);
    let mut challenge = EVIDENCE_CHALLENGE.to_vec();
    challenge.extend_from_slice(&record[..96]);
    record[96..128].copy_from_slice(&startup.authenticate_daemon_proof(&challenge));
    let mut response = EVIDENCE_RESPONSE.to_vec();
    response.extend_from_slice(&record);
    let proof = startup.authenticate_writer_proof(&response);
    (record, proof)
}

#[test]
fn scoped_startup_key_accepts_independent_nonce_and_preserves_one_use_authority() {
    let activation = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
    );
    let mut authority = make_authority(activation.clone());
    let startup = authority
        .derive_linux_writer_startup_authenticator([42; 32], [6; 32], [1; 32], [2; 32])
        .unwrap();
    let writer = CredentialBrokerWriterStartupAuthenticator::from_handoff_payload(
        &startup.handoff_payload(),
    )
    .unwrap();
    let (record, proof) = signed_frame(&writer);
    let mut response = EVIDENCE_RESPONSE.to_vec();
    response.extend_from_slice(&record);
    assert!(!activation.verifies_desktop_transfer(&response, &proof));
    let mut challenge = EVIDENCE_CHALLENGE.to_vec();
    challenge.extend_from_slice(&record[..96]);
    assert!(!activation.verifies_transfer(&challenge, &record[96..128].try_into().unwrap()));
    let witness = authority
        .verify_linux_writer_startup_evidence(&record, &proof, [6; 32], [1; 32], [2; 32], &startup)
        .unwrap();
    assert!(
        authority
            .verify_linux_writer_startup_evidence(
                &record, &proof, [6; 32], [1; 32], [2; 32], &startup
            )
            .is_err()
    );
    assert!(authority.claim_writer_evidence(witness).is_ok());
}

#[test]
fn startup_key_from_foreign_activation_or_context_is_denied() {
    let expected = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
    );
    let foreign = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([43; 32]).unwrap().derive_keys(),
    );
    let mut authority = make_authority(expected);
    let wrong = foreign
        .derive_writer_startup_authenticator([42; 32], [6; 32], [1; 32], [2; 32])
        .unwrap();
    let (record, proof) = signed_frame(&wrong);
    assert!(
        authority
            .verify_linux_writer_startup_evidence(
                &record, &proof, [6; 32], [1; 32], [2; 32], &wrong
            )
            .is_err()
    );

    for (release, channel, publication) in [
        ([7; 32], [1; 32], [2; 32]),
        ([6; 32], [8; 32], [2; 32]),
        ([6; 32], [1; 32], [9; 32]),
    ] {
        let mut authority = make_authority(
            CredentialBrokerTransferAuthenticator::from_protected_activation(
                &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
            ),
        );
        let startup = authority
            .derive_linux_writer_startup_authenticator([42; 32], [6; 32], [1; 32], [2; 32])
            .unwrap();
        let (record, proof) = signed_frame(&startup);
        assert!(
            authority
                .verify_linux_writer_startup_evidence(
                    &record,
                    &proof,
                    release,
                    channel,
                    publication,
                    &startup
                )
                .is_err()
        );
    }

    let mut authority = make_authority(
        CredentialBrokerTransferAuthenticator::from_protected_activation(
            &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
        ),
    );
    let startup = authority
        .derive_linux_writer_startup_authenticator([42; 32], [6; 32], [1; 32], [2; 32])
        .unwrap();
    let (mut record, _) = signed_frame(&startup);
    record[64..96].copy_from_slice(&[44; 32]);
    let mut challenge = EVIDENCE_CHALLENGE.to_vec();
    challenge.extend_from_slice(&record[..96]);
    record[96..128].copy_from_slice(&startup.authenticate_daemon_proof(&challenge));
    let mut response = EVIDENCE_RESPONSE.to_vec();
    response.extend_from_slice(&record);
    let proof = startup.authenticate_writer_proof(&response);
    assert!(
        authority
            .verify_linux_writer_startup_evidence(
                &record, &proof, [6; 32], [1; 32], [2; 32], &startup
            )
            .is_err()
    );
}

#[test]
fn invalid_startup_challenge_proof_burns_one_use_authority() {
    let activation = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
    );
    let mut authority = make_authority(activation);
    let startup = authority
        .derive_linux_writer_startup_authenticator([42; 32], [6; 32], [1; 32], [2; 32])
        .unwrap();
    let (mut record, response_proof) = signed_frame(&startup);
    record[96] ^= 1;
    assert!(authority
        .verify_linux_writer_startup_evidence(
            &record,
            &response_proof,
            [6; 32],
            [1; 32],
            [2; 32],
            &startup,
        )
        .is_err());

    let (valid_record, valid_response_proof) = signed_frame(&startup);
    assert!(authority
        .verify_linux_writer_startup_evidence(
            &valid_record,
            &valid_response_proof,
            [6; 32],
            [1; 32],
            [2; 32],
            &startup,
        )
        .is_err());
}

#[test]
fn invalid_startup_response_proof_burns_one_use_authority() {
    let activation = CredentialBrokerTransferAuthenticator::from_protected_activation(
        &LaunchSecret::from_bytes([41; 32]).unwrap().derive_keys(),
    );
    let mut authority = make_authority(activation);
    let startup = authority
        .derive_linux_writer_startup_authenticator([42; 32], [6; 32], [1; 32], [2; 32])
        .unwrap();
    let (record, mut response_proof) = signed_frame(&startup);
    response_proof[0] ^= 1;
    assert!(authority
        .verify_linux_writer_startup_evidence(
            &record,
            &response_proof,
            [6; 32],
            [1; 32],
            [2; 32],
            &startup,
        )
        .is_err());

    let (valid_record, valid_response_proof) = signed_frame(&startup);
    assert!(authority
        .verify_linux_writer_startup_evidence(
            &valid_record,
            &valid_response_proof,
            [6; 32],
            [1; 32],
            [2; 32],
            &startup,
        )
        .is_err());
}
