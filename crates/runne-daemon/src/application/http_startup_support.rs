use super::replay_authorization::DaemonReplayAuthorization;
use super::*;
use crate::operational_telemetry::compose_operational_telemetry_query;
use runne_application::replay_service::ReplayStorePort;
use runne_domain::id::EventLogLineageId;
use runne_security::project_trust_policy::ProjectTrustPolicyAuthority;
use runne_store::store::StoreTransaction;

pub(super) fn replay_cursor_integrity_secret(
    key: &crate::replay_key::ReplayIntegrityKey,
) -> [u8; 32] {
    key.derive_hmac(b"gocode/replay-cursor-hmac/v1\0")
}

pub(super) fn runtime_session_binding(
    bootstrap: &BootstrapOutcome,
    replay_lineage: EventLogLineageId,
    capabilities: &[&str],
    session_id: [u8; 16],
) -> Result<RuntimeSessionBinding, DaemonError> {
    let schema_hash: [u8; 32] = hex::decode(runne_runtime::bundle::PUBLISHED_BUNDLE_HASH)
        .map_err(|_| DaemonError::Bootstrap("decode schema hash".into()))?
        .try_into()
        .map_err(|_| DaemonError::Bootstrap("invalid schema hash".into()))?;
    let stable = StableRuntimeBinding::new(
        bootstrap.local_session_authority_id,
        ApiPrincipalId::new("local-owner")
            .map_err(|_| DaemonError::Bootstrap("invalid local principal".into()))?,
        replay_lineage,
        runne_runtime::bundle::BUNDLE_ID,
        schema_hash,
        runne_http::runtime_profile::ordered_capability_digest(capabilities),
    )
    .map_err(|_| DaemonError::Bootstrap("build stable local session binding".into()))?;
    RuntimeSessionBinding::new(
        stable,
        bootstrap.launch_identity.daemon_instance_id(),
        bootstrap.launch_generation,
        session_id,
        0,
        Sensitivity::Sensitive,
        *bootstrap.launch_identity.certificate_sha256(),
    )
    .map_err(|_| DaemonError::Bootstrap("build local session binding".into()))
}

pub(super) fn operational_telemetry_state(
    provider_service: Option<&Arc<DaemonCanonicalProviderService>>,
    binding: &RuntimeSessionBinding,
) -> OperationalTelemetryHttpState {
    OperationalTelemetryHttpState::new(compose_operational_telemetry_query(
        provider_service,
        binding.ephemeral().launch_generation(),
    ))
}

/// Composes the production replay authorization + service + HTTP state
/// (T1/NM-06: the authorization consults the process trust authority).
#[allow(clippy::too_many_arguments)]
pub(super) fn compose_replay_http_state(
    replay_store: Arc<dyn ReplayStorePort>,
    replay_integrity_secret: [u8; 32],
    replay_lineage: EventLogLineageId,
    bootstrap_authority_id: [u8; 16],
    local_session_service: Arc<Mutex<LocalSessionService>>,
    trust_authority: Option<&Arc<ProjectTrustPolicyAuthority>>,
    store: &StoreTransaction,
    guard: Arc<dyn ProhibitedContentPort>,
    replay_binding: ReplayHttpBinding,
    baseline_resume_v2_enabled: bool,
) -> ReplayHttpState {
    let authorization = Arc::new(DaemonReplayAuthorization::new(
        bootstrap_authority_id,
        local_session_service,
        super::trust_delivery::replay_trust_gate(trust_authority, store),
    ));
    let replay_service = ReplayService::new(
        replay_store,
        replay_integrity_secret,
        replay_lineage,
        authorization,
    );
    ReplayHttpState::new(
        replay_service,
        replay_binding,
        LimitsConfig::default(),
        guard,
    )
    .with_baseline_resume_v2(baseline_resume_v2_enabled)
}
