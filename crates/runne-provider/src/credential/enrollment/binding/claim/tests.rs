use super::*;
use crate::credential::enrollment::{
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLifecycleRevision,
    CredentialMeasurementSnapshot, CredentialTicketAttempt,
};

#[test]
fn credential_enrollment_claim_binding_changes_for_each_approved_field() {
    let binding = claim_binding();
    let digest = binding.digest();
    macro_rules! changed {
        ($field:ident, $value:expr) => {{
            let mut candidate = binding.clone();
            candidate.$field = $value;
            assert_ne!(candidate.digest(), digest, stringify!($field));
        }};
    }
    changed!(candidate_source_identity, measured(101));
    changed!(release_manifest_digest, measured(102));
    changed!(desktop_executable_identity, measured(103));
    changed!(writer_executable_identity, measured(104));
    changed!(reader_executable_identity, measured(105));
    changed!(contract_bundle_digest, measured(106));
    changed!(daemon_authority_id, measured(107));
    changed!(database_generation, 2);
    changed!(protected_session_id, measured(108));
    changed!(desktop_supervisor_generation, 2);
    changed!(writer_launch_id, measured(109));
    changed!(writer_process_start_identity, measured(110));
    changed!(writer_process_handle_identity, measured(111));
    changed!(broker_channel_binding, measured(112));
    changed!(continuation_binding_digest, measured(113));
    changed!(
        operation_id,
        CredentialOperationId::from_bytes([114; 16]).unwrap()
    );
    changed!(ticket_attempt, CredentialTicketAttempt::new(2).unwrap());
    changed!(ticket_digest, measured(115));
    changed!(provider_id, ProviderId::new("anthropic").unwrap());
    changed!(action, CredentialOperationAction::Revoke);
    changed!(credential_version, version("openai", 2));
    changed!(
        expected_lifecycle_revision,
        CredentialLifecycleRevision::new(2).unwrap()
    );
    changed!(expected_prior_fence, CredentialFence::new(2).unwrap());
    changed!(issued_at_high_water, 2);
    changed!(expires_at_high_water, 3);
}

#[test]
fn credential_claim_binding_rejects_a_continuation_digest_not_independently_measured() {
    assert!(
        CredentialClaimBinding::new(measurements(13), &claim(measured(16), measured(17)),).is_err()
    );
}

#[test]
fn credential_claim_binding_rejects_a_noncanonical_process_release_digest() {
    assert!(
        CredentialClaimBinding::new(measurements(13), &claim(measured(13), measured(17)),).is_err()
    );
}

fn claim_binding() -> CredentialClaimBinding {
    let claim = claim(measured(13), canonical_claim_digest());
    let binding = CredentialClaimBinding::new(measurements(13), &claim).unwrap();
    assert_eq!(binding.operation_id(), claim.operation_id());
    binding
}

fn canonical_claim_digest() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([
        0x54, 0xb7, 0xa4, 0x5c, 0x10, 0x0d, 0x59, 0x20, 0x54, 0xe5, 0x7d, 0xa1, 0xbd, 0x70, 0x88,
        0x86, 0x62, 0xc9, 0x9c, 0xae, 0x13, 0x0a, 0x8d, 0x20, 0xda, 0x36, 0xca, 0x6b, 0x3c, 0x54,
        0x27, 0xf6,
    ])
    .unwrap()
}

fn measurements(continuation: u8) -> CredentialMeasurementSnapshot {
    let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    CredentialMeasurementSnapshot::new(
        measurements.candidate_source_identity([1; 32]).unwrap(),
        measurements.release_manifest_digest([2; 32]).unwrap(),
        measurements.desktop_executable_identity([3; 32]).unwrap(),
        measurements.writer_executable_identity([4; 32]).unwrap(),
        measurements.reader_executable_identity([5; 32]).unwrap(),
        measurements.contract_bundle_digest([6; 32]).unwrap(),
        measurements.daemon_authority_id([7; 32]).unwrap(),
        measurements.protected_session_id([8; 32]).unwrap(),
        measurements.writer_launch_id([9; 32]).unwrap(),
        measurements
            .writer_process_start_identity([10; 32])
            .unwrap(),
        measurements
            .writer_process_handle_identity([11; 32])
            .unwrap(),
        measurements.broker_channel_binding([12; 32]).unwrap(),
        measurements
            .continuation_binding_digest([continuation; 32])
            .unwrap(),
    )
    .unwrap()
}

fn claim(
    continuation: CredentialBindingDigest,
    process_release: CredentialBindingDigest,
) -> ClaimCredentialOperation {
    ClaimCredentialOperation::new(
        CredentialOperationId::from_bytes([14; 16]).unwrap(),
        CredentialTicketAttempt::new(1).unwrap(),
        measured(15),
        continuation,
        process_release,
        ProviderId::new("openai").unwrap(),
        CredentialOperationAction::Pair,
        Some(version("openai", 1)),
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        1,
        1,
        1,
        2,
    )
    .unwrap()
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn version(provider: &str, value: u64) -> CredentialVersionRef {
    CredentialVersionRef::new(ProviderId::new(provider).unwrap(), value).unwrap()
}
