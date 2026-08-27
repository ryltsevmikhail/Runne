use std::time::{SystemTime, UNIX_EPOCH};

use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    CompleteCredentialOperation, CredentialAuthorityPair, CredentialBindingDigest,
    CredentialEnrollmentAuthorityPair, CredentialEnrollmentMeasurementAuthority, CredentialFence,
    CredentialInstallationOwnerId, CredentialLifecycleError, CredentialLifecycleRevision,
    CredentialMeasurementSnapshot, CredentialNativeEffectDisposition, CredentialOperationAction,
    CredentialOperationId, CredentialReadbackDisposition, CredentialReadinessDisposition,
    CredentialReadinessObservation, CredentialReadinessRevision, CredentialVersionRef,
    IssueCredentialTicketDigest, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
    ProviderId,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;

const MAX_COMPLETE_ATTEMPTS: usize = 3;

pub fn credential(
    database: &super::validated_reopen::ProviderTestDatabase,
    provider: &str,
    discriminator: u8,
) -> SqliteProviderCredentialLifecycleStore {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment, measurement_authority) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        database.connection(),
        lifecycle,
        enrollment,
    )
    .unwrap();
    let now = unix_seconds();
    let provider = ProviderId::new(provider).unwrap();
    let operation = CredentialOperationId::from_bytes([discriminator; 16]).unwrap();
    let active = CredentialVersionRef::new(provider.clone(), 1).unwrap();
    let ticket = digest(discriminator.wrapping_add(2));
    let continuation = digest(discriminator.wrapping_add(3));

    let qualified_release = measurement_authority
        .issue_qualified_credential_release_tuple(
            measurement_authority
                .release_manifest_digest([201; 32])
                .unwrap(),
        )
        .unwrap();
    let qualified_release_digest = qualified_release.digest();
    ProviderCredentialEnrollmentStore::begin(
        &store,
        BeginCredentialOperation::new(
            CommandId::from_bytes([discriminator.wrapping_add(20); 16]),
            IdempotencyKey::new(format!("online-credential-{discriminator}")).unwrap(),
            operation,
            CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
            provider.clone(),
            CredentialOperationAction::Pair,
            Some(active.clone()),
            None,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            digest(discriminator.wrapping_add(1)),
            now.checked_add(600).unwrap(),
        )
        .unwrap()
        .with_qualified_release_tuple(qualified_release),
    )
    .unwrap();
    let receipt = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        &store,
        IssueCredentialTicketDigest::new(operation, ticket, continuation, 600).unwrap(),
    )
    .unwrap();
    let draft = ClaimCredentialOperation::new(
        receipt,
        ticket,
        continuation,
        digest(discriminator.wrapping_add(4)),
        1,
        1,
    )
    .unwrap();
    let snapshot = measurements(&measurement_authority, &draft);
    let binding = measurement_authority
        .measure_claim_operation(&snapshot, &draft)
        .unwrap();
    let claim = measurement_authority
        .seal_claim_operation(
            snapshot,
            draft.bind_process_release_digest(binding).unwrap(),
        )
        .unwrap();
    ProviderCredentialEnrollmentStore::claim(&store, claim).unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(operation, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let readback = || {
        BindCredentialReadback::new(
            operation,
            CredentialReadbackDisposition::ExactVersion,
            digest(discriminator.wrapping_add(5)),
        )
        .unwrap()
    };
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback()).unwrap();
    for attempt in 0..MAX_COMPLETE_ATTEMPTS {
        let observed = unix_seconds();
        let readiness = CredentialReadinessObservation::new(
            CredentialOperationId::from_bytes([discriminator.wrapping_add(100); 16]).unwrap(),
            Some(operation),
            provider.clone(),
            CredentialLifecycleRevision::new(2).unwrap(),
            CredentialReadinessRevision::new(2).unwrap(),
            CredentialReadinessDisposition::Ready,
            Some(CredentialBindingDigest::from_measured(*active.ref_digest()).unwrap()),
            qualified_release_digest,
            i64::try_from(observed).unwrap(),
        )
        .unwrap();
        let complete = CompleteCredentialOperation::new(
            operation,
            readback(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness);
        match ProviderCredentialEnrollmentStore::complete(&store, complete) {
            Ok(_) => break,
            Err(CredentialLifecycleError::Conflict)
                if attempt + 1 < MAX_COMPLETE_ATTEMPTS && unix_seconds() > observed =>
            {
                continue;
            }
            Err(error) => panic!("online credential completion failed: {error:?}"),
        }
    }
    store
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn measurements(
    authority: &CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> CredentialMeasurementSnapshot {
    CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([200; 32]).unwrap(),
        authority.release_manifest_digest([201; 32]).unwrap(),
        authority.desktop_executable_identity([202; 32]).unwrap(),
        authority.writer_executable_identity([203; 32]).unwrap(),
        authority.reader_executable_identity([204; 32]).unwrap(),
        authority.contract_bundle_digest([205; 32]).unwrap(),
        authority.daemon_authority_id([206; 32]).unwrap(),
        authority.protected_session_id([207; 32]).unwrap(),
        authority
            .desktop_supervisor_generation(claim.desktop_supervisor_generation())
            .unwrap(),
        authority.writer_launch_id([208; 32]).unwrap(),
        authority.writer_process_start_identity([209; 32]).unwrap(),
        authority.writer_process_handle_identity([210; 32]).unwrap(),
        authority.broker_channel_binding([211; 32]).unwrap(),
        authority
            .continuation_binding_digest(claim.continuation_binding_digest().as_bytes())
            .unwrap(),
    )
    .unwrap()
}
