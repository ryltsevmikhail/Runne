use super::*;
use crate::operational_telemetry::compose_operational_telemetry_query;

pub(super) fn replay_cursor_integrity_secret(
    key: &crate::replay_key::ReplayIntegrityKey,
) -> [u8; 32] {
    key.derive_hmac(b"gocode/replay-cursor-hmac/v1\0")
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

pub(super) fn provider_credential_control() -> Arc<dyn runne_api::ProviderCredentialControlHostPort>
{
    let store: Arc<dyn runne_secure_store::ProviderCredentialStore> =
        Arc::new(runne_secure_store::NativeProviderCredentialStore::new());
    Arc::new(
        super::provider_credential_control::DaemonProviderCredentialControl::new(
            store,
            crate::canonical_provider::readiness::credential_access_policy(
                runne_secure_store::ProviderCredentialId::OpenAi,
            )
            .ok(),
        ),
    )
}
