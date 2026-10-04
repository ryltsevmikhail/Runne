use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    CompleteCredentialOperation, CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialFence, CredentialInstallationOwnerId, CredentialLifecycleRevision,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationId,
    CredentialQualifiedReleaseTuple, CredentialReadbackDisposition, CredentialReadinessDisposition,
    CredentialReadinessObservation, CredentialReadinessRevision, CredentialVersionRef,
    IssueCredentialTicketDigest, ObserveNativeEffect, ProviderCredentialEnrollmentStore,
    ProviderId,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

pub(super) fn ready(connection: ManagedConnection) -> SqliteProviderCredentialLifecycleStore {
    let (lifecycle, _) = runne_provider::CredentialAuthorityPair::new().split();
    let (enrollment, measurement_authority) = CredentialEnrollmentAuthorityPair::new().split();
    let store = SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
        connection, lifecycle, enrollment,
    )
    .unwrap();
    let provider = ProviderId::new("fixture-provider").unwrap();
    let operation = operation_id(51);
    let manifest = [92; 32];
    let release = qualified_release(&measurement_authority, manifest);
    let release_digest = release.digest();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let input = BeginCredentialOperation::new(
        CommandId::from_bytes([71; 16]),
        IdempotencyKey::new("unknown-successor-credential-pair").unwrap(),
        operation,
        CredentialInstallationOwnerId::from_bytes([42; 32]).unwrap(),
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(CredentialVersionRef::new(provider.clone(), 1).unwrap()),
        None,
        CredentialLifecycleRevision::new(1).unwrap(),
        CredentialFence::new(1).unwrap(),
        digest(52),
        now + 10_000,
    )
    .unwrap()
    .with_qualified_release_tuple(release);
    ProviderCredentialEnrollmentStore::begin(&store, input).unwrap();
    let continuation = digest(53);
    ProviderCredentialEnrollmentStore::attach_process(
        &store,
        runne_provider::AttachCredentialProcess::new(operation, continuation).unwrap(),
    )
    .unwrap();
    let issued = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        &store,
        IssueCredentialTicketDigest::new(operation, digest(54), continuation, 1_000).unwrap(),
    )
    .unwrap();
    let draft =
        ClaimCredentialOperation::new(issued, digest(54), continuation, digest(55), 1, 1).unwrap();
    let snapshot = measurement_snapshot(&measurement_authority, &draft, manifest);
    let measured = measurement_authority
        .measure_claim_operation(&snapshot, &draft)
        .unwrap();
    let claim = measurement_authority
        .seal_claim_operation(
            snapshot,
            draft.bind_process_release_digest(measured).unwrap(),
        )
        .unwrap();
    ProviderCredentialEnrollmentStore::claim(&store, claim).unwrap();
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        &store,
        ObserveNativeEffect::new(operation, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .unwrap();
    let readback = BindCredentialReadback::new(
        operation,
        CredentialReadbackDisposition::ExactVersion,
        digest(56),
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::bind_readback(&store, readback).unwrap();
    let observation_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let observed_head = ProviderCredentialEnrollmentStore::safe_snapshot(&store, &provider)
        .unwrap()
        .observed_at_high_water();
    let readiness_time = i64::try_from(observation_now)
        .unwrap_or(i64::MAX)
        .max(observed_head);
    let readiness = CredentialReadinessObservation::new(
        operation_id(151),
        Some(operation),
        provider.clone(),
        CredentialLifecycleRevision::new(2).unwrap(),
        CredentialReadinessRevision::new(2).unwrap(),
        CredentialReadinessDisposition::Ready,
        Some(
            CredentialBindingDigest::from_measured(
                *CredentialVersionRef::new(provider.clone(), 1)
                    .unwrap()
                    .ref_digest(),
            )
            .unwrap(),
        ),
        release_digest,
        readiness_time,
    )
    .unwrap();
    ProviderCredentialEnrollmentStore::complete(
        &store,
        CompleteCredentialOperation::new(
            operation,
            BindCredentialReadback::new(
                operation,
                CredentialReadbackDisposition::ExactVersion,
                digest(56),
            )
            .unwrap(),
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
        )
        .unwrap()
        .with_readiness_observation(readiness),
    )
    .unwrap();
    store
}

fn measurement_snapshot(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
    release: [u8; 32],
) -> runne_provider::CredentialMeasurementSnapshot {
    runne_provider::CredentialMeasurementSnapshot::new(
        authority.candidate_source_identity([200; 32]).unwrap(),
        authority.release_manifest_digest(release).unwrap(),
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

fn qualified_release(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    manifest: [u8; 32],
) -> CredentialQualifiedReleaseTuple {
    let manifest = authority.release_manifest_digest(manifest).unwrap();
    authority
        .issue_qualified_credential_release_tuple(manifest)
        .unwrap()
}

fn operation_id(value: u8) -> CredentialOperationId {
    CredentialOperationId::from_bytes([value; 16]).unwrap()
}
fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}
