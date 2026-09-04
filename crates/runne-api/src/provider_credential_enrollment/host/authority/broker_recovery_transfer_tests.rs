use super::*;
use crate::LaunchSecret;

#[test]
fn recovery_transfer_uses_current_issuer_session_and_keys_without_native_intent() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let base = issuer.issue_base([1; 32], [2; 32], [3; 32], 4, [5; 32], 6, [7; 32]).unwrap();
    let keys = LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys();
    let transfer = issuer.issue_recovery_broker_transfer(&keys, &base).unwrap();
    let witness = base.credential_broker_handoff_witness();
    assert!(transfer.matches_handoff(&witness, &[3; 32]));
    assert!(!transfer.matches_handoff(&witness, &[9; 32]));
    let expected = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let record = b"recovery endpoint evidence";
    assert_eq!(transfer.authenticate_daemon_transfer(record), expected.authenticate_daemon_transfer(record));
    let foreign_keys = LaunchSecret::from_bytes([9; 32]).unwrap().derive_keys();
    let foreign = CredentialBrokerTransferAuthenticator::from_protected_activation(&foreign_keys);
    assert_ne!(transfer.authenticate_daemon_transfer(record), foreign.authenticate_daemon_transfer(record));
}

#[test]
fn recovery_transfer_rejects_foreign_base_even_with_identical_fields() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let (foreign, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let base = foreign.issue_base([1; 32], [2; 32], [3; 32], 4, [5; 32], 6, [7; 32]).unwrap();
    let keys = LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys();
    assert!(issuer.issue_recovery_broker_transfer(&keys, &base).is_err());
}

#[test]
fn recovery_transfer_writer_evidence_is_one_use_and_instance_bound() {
    let (issuer, _) = ProviderCredentialRequestAuthorityPair::new().split();
    let base = issuer.issue_base([1; 32], [2; 32], [3; 32], 4, [5; 32], 6, [7; 32]).unwrap();
    let keys = LaunchSecret::from_bytes([8; 32]).unwrap().derive_keys();
    let mut first = issuer.issue_recovery_broker_transfer(&keys, &base).unwrap();
    let second = issuer.issue_recovery_broker_transfer(&keys, &base).unwrap();
    let desktop = CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
    let mut record = [0_u8; 256];
    record[..32].copy_from_slice(&[11; 32]);
    record[32..64].copy_from_slice(&[12; 32]);
    record[64..96].copy_from_slice(&[13; 32]);
    let mut challenge = EVIDENCE_CHALLENGE.to_vec();
    challenge.extend_from_slice(&record[..96]);
    record[96..128].copy_from_slice(&first.authenticate_daemon_transfer(&challenge));
    record[128..160].copy_from_slice(&[14; 32]);
    record[160..192].copy_from_slice(&[15; 32]);
    record[192..224].copy_from_slice(&[2; 32]);
    record[224..256].copy_from_slice(&[16; 32]);
    let mut response = EVIDENCE_RESPONSE.to_vec();
    response.extend_from_slice(&record);
    let proof = desktop.authenticate_transfer(&response);
    let evidence = first.verify_writer_evidence(&record, &proof, [2; 32], [11; 32], [12; 32]).unwrap();
    assert!(first.verify_writer_evidence(&record, &proof, [2; 32], [11; 32], [12; 32]).is_err());
    assert!(second.claim_writer_evidence(evidence).is_err());
}
