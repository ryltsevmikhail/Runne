use super::*;
use crate::credential::enrollment::{
    CredentialEnrollmentAuthorityPair, CredentialFence, CredentialInstallationOwnerId,
    CredentialLifecycleRevision, CredentialMeasurementSnapshot, CredentialOperationMetadata,
    CredentialOperationSnapshot, CredentialOperationState, CredentialTicketAttempt,
    IssuedCredentialTicketAttempt,
};
use crate::{CredentialVersionRef, ProviderId};

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
    changed!(
        installation_owner_id,
        CredentialInstallationOwnerId::from_bytes([115; 32]).unwrap()
    );
    changed!(ticket_attempt, CredentialTicketAttempt::new(2).unwrap());
    changed!(ticket_digest, measured(116));
    changed!(provider_id, ProviderId::new("anthropic").unwrap());
    changed!(action, CredentialOperationAction::Revoke);
    changed!(credential_version, Some(version("openai", 2)));
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
        CredentialClaimBinding::new(measurements(13, 1), &claim(measured(16), measured(17)),)
            .is_err()
    );
}

#[test]
fn credential_claim_binding_rejects_a_noncanonical_process_release_digest() {
    assert!(
        CredentialClaimBinding::new(measurements(13, 1), &claim(measured(13), measured(17)),)
            .is_err()
    );
}

#[test]
fn credential_claim_binding_rejects_a_substituted_supervisor_generation() {
    let mut binding = claim_binding();
    binding.desktop_supervisor_generation = 2;
    let substituted = claim_with_supervisor(measured(13), binding.digest(), 2);

    assert!(CredentialClaimBinding::new(measurements(13, 1), &substituted).is_err());
}

fn claim_binding() -> CredentialClaimBinding {
    let claim = claim(measured(13), canonical_claim_digest());
    let binding = CredentialClaimBinding::new(measurements(13, 1), &claim).unwrap();
    assert_eq!(binding.operation_id(), claim.operation_id());
    binding
}

fn canonical_claim_digest() -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([
        0x51, 0x27, 0xa0, 0xaf, 0xf8, 0x77, 0xdf, 0xe3, 0x6e, 0xd7, 0x86, 0x09, 0xb5, 0x88, 0x27,
        0x22, 0xc6, 0xa1, 0xce, 0xc4, 0x64, 0xb9, 0x1f, 0xe8, 0xc0, 0x9f, 0x88, 0x77, 0xa1, 0xa3,
        0x68, 0xa1,
    ])
    .unwrap()
}

fn measurements(continuation: u8, supervisor_generation: u64) -> CredentialMeasurementSnapshot {
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
        measurements
            .desktop_supervisor_generation(supervisor_generation)
            .unwrap(),
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
    claim_with_supervisor(continuation, process_release, 1)
}

fn claim_with_supervisor(
    continuation: CredentialBindingDigest,
    process_release: CredentialBindingDigest,
    supervisor_generation: u64,
) -> ClaimCredentialOperation {
    ClaimCredentialOperation::new(
        receipt(),
        measured(15),
        continuation,
        process_release,
        supervisor_generation,
        1,
    )
    .unwrap()
}

fn receipt() -> IssuedCredentialTicketAttempt {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    let operation = CredentialOperationId::from_bytes([14; 16]).unwrap();
    let provider = ProviderId::new("openai").unwrap();
    let snapshot = CredentialOperationSnapshot::new(
        operation,
        provider.clone(),
        CredentialOperationAction::Pair,
        CredentialOperationState::Prepared,
        Some(CredentialVersionRef::new(provider, 1).unwrap()),
        None,
        CredentialOperationMetadata::new(
            runne_domain::id::CommandId::from_bytes([14; 16]),
            runne_domain::id::IdempotencyKey::new("claim-binding").unwrap(),
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            measured(16),
            1,
            1,
        )
        .unwrap(),
    )
    .unwrap();
    store
        .hydrate_issued_credential_ticket_attempt(
            snapshot,
            CredentialTicketAttempt::new(1).unwrap(),
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
