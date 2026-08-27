use std::sync::Arc;

use runne_domain::id::{CommandId, IdempotencyKey};
use runne_provider::{
    BeginCredentialOperation, BindCredentialReadback, ClaimCredentialOperation,
    CompleteCredentialOperation, CredentialAuthorityPair, CredentialBindingDigest,
    CredentialEnrollmentAuthorityPair, CredentialLifecycleRevision, CredentialMeasurementSnapshot,
    CredentialNativeEffectDisposition, CredentialOperationAction, CredentialOperationId,
    CredentialReadbackDisposition, CredentialReadinessDisposition, CredentialReadinessObservation,
    CredentialReadinessRevision, CredentialVersionRef, IssueCredentialTicketDigest,
    ObserveNativeEffect, ProviderCredentialEnrollmentStore, ProviderId,
};
use runne_secure_store::ProviderCredentialId;
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

use crate::error::DaemonError;

const FIXTURE_OPERATION: [u8; 16] = [0xD6; 16];

/// Seeds one sealed online credential lifecycle only for the loopback runtime.
/// A restarted fixture reads the already-completed authority state unchanged.
pub(super) fn compose(
    connection: ManagedConnection,
    credential_id: ProviderCredentialId,
) -> Result<Arc<SqliteProviderCredentialLifecycleStore>, DaemonError> {
    let provider = ProviderId::new(credential_id.account()).map_err(|_| unavailable())?;
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment, measurements) = CredentialEnrollmentAuthorityPair::new().split();
    let store = Arc::new(
        SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
            connection, lifecycle, enrollment,
        )
        .map_err(|_| unavailable())?,
    );
    let snapshot =
        ProviderCredentialEnrollmentStore::begin_admission_snapshot(store.as_ref(), &provider)
            .map_err(|_| unavailable())?;
    if snapshot.active_version().is_some() {
        return Ok(store);
    }
    provision_online(store.as_ref(), provider, snapshot, measurements)?;
    Ok(store)
}

fn provision_online(
    store: &SqliteProviderCredentialLifecycleStore,
    provider: ProviderId,
    snapshot: runne_provider::CredentialLifecycleSnapshot,
    measurements: runne_provider::CredentialEnrollmentMeasurementAuthority,
) -> Result<(), DaemonError> {
    let now = chrono::Utc::now().timestamp();
    let expiry = now.checked_add(600).ok_or_else(unavailable)?;
    let operation =
        CredentialOperationId::from_bytes(FIXTURE_OPERATION).map_err(|_| unavailable())?;
    let active = CredentialVersionRef::new(provider.clone(), snapshot.next_credential_version())
        .map_err(|_| unavailable())?;
    let release = measurements
        .issue_qualified_credential_release_tuple(
            measurements
                .release_manifest_digest([0xD1; 32])
                .map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
    let release_digest = release.digest();
    let begin = BeginCredentialOperation::new(
        CommandId::from_bytes([0xD2; 16]),
        IdempotencyKey::new("loopback-online-credential-v1").map_err(|_| unavailable())?,
        operation,
        runne_provider::CredentialInstallationOwnerId::from_bytes([0xD3; 32])
            .map_err(|_| unavailable())?,
        provider.clone(),
        CredentialOperationAction::Pair,
        Some(active.clone()),
        None,
        snapshot.lifecycle_revision(),
        snapshot.fence(),
        digest(0xD4),
        u64::try_from(expiry).map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?
    .with_qualified_release_tuple(release);
    ProviderCredentialEnrollmentStore::begin(store, begin).map_err(|_| unavailable())?;
    let receipt = ProviderCredentialEnrollmentStore::issue_ticket_attempt(
        store,
        IssueCredentialTicketDigest::new(operation, digest(0xD5), digest(0xD6), 600)
            .map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?;
    let draft =
        ClaimCredentialOperation::new(receipt, digest(0xD5), digest(0xD6), digest(0xD7), 1, 1)
            .map_err(|_| unavailable())?;
    let claim_measurements = measurement_snapshot(&measurements, &draft)?;
    let binding = measurements
        .measure_claim_operation(&claim_measurements, &draft)
        .map_err(|_| unavailable())?;
    let claim = measurements
        .seal_claim_operation(
            claim_measurements,
            draft
                .bind_process_release_digest(binding)
                .map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
    ProviderCredentialEnrollmentStore::claim(store, claim).map_err(|_| unavailable())?;
    ProviderCredentialEnrollmentStore::mark_native_effect_observed(
        store,
        ObserveNativeEffect::new(operation, CredentialNativeEffectDisposition::PossibleEffect),
    )
    .map_err(|_| unavailable())?;
    let readback = || {
        BindCredentialReadback::new(
            operation,
            CredentialReadbackDisposition::ExactVersion,
            digest(0xD8),
        )
        .map_err(|_| unavailable())
    };
    ProviderCredentialEnrollmentStore::bind_readback(store, readback()?)
        .map_err(|_| unavailable())?;
    let readiness = CredentialReadinessObservation::new(
        CredentialOperationId::from_bytes([0xD9; 16]).map_err(|_| unavailable())?,
        Some(operation),
        provider,
        CredentialLifecycleRevision::new(snapshot.lifecycle_revision().get() + 1)
            .map_err(|_| unavailable())?,
        CredentialReadinessRevision::new(snapshot.readiness_revision().get() + 1)
            .map_err(|_| unavailable())?,
        CredentialReadinessDisposition::Ready,
        Some(
            CredentialBindingDigest::from_measured(*active.ref_digest())
                .map_err(|_| unavailable())?,
        ),
        release_digest,
        now,
    )
    .map_err(|_| unavailable())?;
    ProviderCredentialEnrollmentStore::complete(
        store,
        CompleteCredentialOperation::new(
            operation,
            readback()?,
            snapshot.lifecycle_revision(),
            snapshot.fence(),
        )
        .map_err(|_| unavailable())?
        .with_readiness_observation(readiness),
    )
    .map_err(|_| unavailable())?;
    Ok(())
}

fn measurement_snapshot(
    authority: &runne_provider::CredentialEnrollmentMeasurementAuthority,
    claim: &ClaimCredentialOperation,
) -> Result<CredentialMeasurementSnapshot, DaemonError> {
    CredentialMeasurementSnapshot::new(
        authority
            .candidate_source_identity([0xE1; 32])
            .map_err(|_| unavailable())?,
        authority
            .release_manifest_digest([0xE2; 32])
            .map_err(|_| unavailable())?,
        authority
            .desktop_executable_identity([0xE3; 32])
            .map_err(|_| unavailable())?,
        authority
            .writer_executable_identity([0xE4; 32])
            .map_err(|_| unavailable())?,
        authority
            .reader_executable_identity([0xE5; 32])
            .map_err(|_| unavailable())?,
        authority
            .contract_bundle_digest([0xE6; 32])
            .map_err(|_| unavailable())?,
        authority
            .daemon_authority_id([0xE7; 32])
            .map_err(|_| unavailable())?,
        authority
            .protected_session_id([0xE8; 32])
            .map_err(|_| unavailable())?,
        authority
            .desktop_supervisor_generation(claim.desktop_supervisor_generation())
            .map_err(|_| unavailable())?,
        authority
            .writer_launch_id([0xE9; 32])
            .map_err(|_| unavailable())?,
        authority
            .writer_process_start_identity([0xEA; 32])
            .map_err(|_| unavailable())?,
        authority
            .writer_process_handle_identity([0xEB; 32])
            .map_err(|_| unavailable())?,
        authority
            .broker_channel_binding([0xEC; 32])
            .map_err(|_| unavailable())?,
        authority
            .continuation_binding_digest(claim.continuation_binding_digest().as_bytes())
            .map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())
}

fn digest(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).expect("fixed fixture digest")
}

fn unavailable() -> DaemonError {
    DaemonError::Bootstrap("loopback online credential fixture unavailable".into())
}
