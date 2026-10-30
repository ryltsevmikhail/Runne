use std::sync::Arc;

#[cfg(test)]
use runne_provider::{CredentialAuthorityPair, CredentialEnrollmentAuthorityPair};
use runne_provider::{
    CredentialEnrollmentMeasurementAuthority, CredentialEnrollmentStoreAuthority,
};
use runne_secure_store::{
    ProviderCredentialId, ProviderCredentialReadback, ProviderCredentialStatus,
};
use runne_store::provider::SqliteProviderCredentialLifecycleStore;
use runne_store::schema::ManagedConnection;

use super::{CanonicalProviderEffect, ProviderEffectFactory, credential_access_policy};
use crate::error::DaemonError;

pub(super) struct CredentialBoundary {
    pub(super) store: Arc<SqliteProviderCredentialLifecycleStore>,
    pub(super) readback: Option<Arc<dyn ProviderCredentialReadback>>,
    pub(super) adapter: Arc<dyn CanonicalProviderEffect>,
    pub(super) tool_adapter: Option<Arc<dyn CanonicalProviderEffect>>,
    pub(super) status: ProviderCredentialStatus,
    pub(super) enrollment_authorities: Option<CredentialEnrollmentControlAuthorities>,
    #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
    pub(super) credential_service:
        Option<Arc<crate::protected_activation::CredentialServiceRuntimeGateway>>,
    pub(super) defer_initial_reconciliation: bool,
}

pub(super) struct CredentialEnrollmentControlAuthorities {
    pub(super) measurements: CredentialEnrollmentMeasurementAuthority,
    pub(super) store: CredentialEnrollmentStoreAuthority,
}

pub(super) fn production(
    connection: ManagedConnection,
    credential_id: ProviderCredentialId,
    adapter_factory: &ProviderEffectFactory,
    protected_activation: bool,
    deepseek_tools: bool,
    observer: Option<Arc<dyn runne_daemon_deepseek_effect::DeepSeekEffectObserver>>,
) -> Result<CredentialBoundary, DaemonError> {
    let credentials = super::super::credential_reader::compose(
        connection,
        credential_id,
        credential_access_policy(credential_id)
            .map_err(|_| DaemonError::Bootstrap("provider_compose_access_policy".into()))?,
        protected_activation,
    )
    .map_err(|error| match &error {
        DaemonError::Bootstrap(code) if code.starts_with("provider_compose_") => error,
        _ => DaemonError::Bootstrap("provider_compose_native_reader".into()),
    })?;
    let adapter = adapter_factory(
        Arc::clone(&credentials.dispatch),
        Arc::clone(&credentials.store),
    )
    .map_err(|_| DaemonError::Bootstrap("provider_compose_primary_adapter".into()))?;
    let tool_adapter = if deepseek_tools {
        if credential_id != ProviderCredentialId::DeepSeek || !protected_activation {
            return Err(DaemonError::Bootstrap(
                "tool provider binding rejected".into(),
            ));
        }
        let tool = match observer {
            Some(observer) => {
                <dyn runne_daemon_deepseek_effect::DeepSeekEffect>::production_tools_with_observer(
                    Arc::clone(&credentials.dispatch),
                    observer,
                )
            }
            None => <dyn runne_daemon_deepseek_effect::DeepSeekEffect>::production_tools(
                Arc::clone(&credentials.dispatch),
            ),
        };
        Some(
            tool.map(crate::canonical_provider::deepseek_effect_adapter)
                .map_err(|_| DaemonError::Bootstrap("tool provider unavailable".into()))?,
        )
    } else {
        None
    };
    Ok(CredentialBoundary {
        store: credentials.store,
        readback: Some(credentials.readback),
        adapter,
        tool_adapter,
        status: ProviderCredentialStatus::Missing,
        enrollment_authorities: Some(CredentialEnrollmentControlAuthorities {
            measurements: credentials.measurements,
            store: credentials.enrollment_store_authority,
        }),
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: credentials.credential_service,
        defer_initial_reconciliation: credentials.defer_initial_reconciliation,
    })
}

/// Builds the separately enrolled background realm and wires its durable
/// context resolver plus fresh current-head recovery authorizer.
pub(super) fn production_background(
    connection: ManagedConnection,
    execution: Arc<runne_store::provider::SqliteProviderExecutionStore>,
    context: Arc<dyn runne_provider::ProviderRecoveryDispatchContextProvider>,
    protected_activation: bool,
    recovery_gate: Arc<super::super::saved_remote_gate::SavedRemoteBlockingGate>,
) -> Result<CredentialBoundary, DaemonError> {
    let credential_id = ProviderCredentialId::OpenAiBackground;
    let credentials = super::super::credential_reader::compose(
        connection,
        credential_id,
        credential_access_policy(credential_id)?,
        protected_activation,
    )?;
    let authorizer = Arc::new(
        crate::canonical_provider::recovery_authorizer::DaemonProviderRecoveryAuthorizer::new(
            Arc::clone(&credentials.store),
            Arc::clone(&execution),
            Arc::clone(&credentials.dispatch),
            recovery_gate,
        ),
    );
    let adapter = runne_daemon_openai_effect::production_background_effect_from_materializer(
        Arc::clone(&credentials.dispatch),
        context,
        authorizer,
    )
    .map(crate::canonical_provider::openai_effect_adapter)
    .map_err(|_| DaemonError::Bootstrap("OpenAI background adapter unavailable".into()))?;
    Ok(CredentialBoundary {
        store: credentials.store,
        readback: Some(credentials.readback),
        adapter,
        tool_adapter: None,
        status: ProviderCredentialStatus::Missing,
        enrollment_authorities: Some(CredentialEnrollmentControlAuthorities {
            measurements: credentials.measurements,
            store: credentials.enrollment_store_authority,
        }),
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: credentials.credential_service,
        defer_initial_reconciliation: credentials.defer_initial_reconciliation,
    })
}

// fixture-only capability begin
#[cfg(test)]
pub(super) fn fixture_missing(
    connection: ManagedConnection,
    _credential_id: ProviderCredentialId,
    adapter: Arc<dyn CanonicalProviderEffect>,
) -> Result<CredentialBoundary, DaemonError> {
    let (lifecycle, _) = CredentialAuthorityPair::new().split();
    let (enrollment, _) = CredentialEnrollmentAuthorityPair::new().split();
    let store = Arc::new(
        SqliteProviderCredentialLifecycleStore::open_with_connection_and_authorities(
            connection, lifecycle, enrollment,
        )
        .map_err(|_| DaemonError::Bootstrap("provider credential store unavailable".into()))?,
    );
    Ok(CredentialBoundary {
        store,
        readback: None,
        adapter,
        tool_adapter: None,
        status: ProviderCredentialStatus::Missing,
        enrollment_authorities: None,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: None,
        defer_initial_reconciliation: false,
    })
}

#[cfg(test)]
pub(super) fn fixture_enrolled(
    connection: ManagedConnection,
    credential_id: ProviderCredentialId,
    adapter: Arc<dyn CanonicalProviderEffect>,
) -> Result<CredentialBoundary, DaemonError> {
    let store = super::fixture_credentials::compose(connection, credential_id)?;
    Ok(CredentialBoundary {
        store,
        readback: None,
        adapter,
        tool_adapter: None,
        status: ProviderCredentialStatus::Configured,
        enrollment_authorities: None,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: None,
        defer_initial_reconciliation: false,
    })
}

#[cfg(test)]
pub(super) fn fixture(
    connection: ManagedConnection,
    owner: [u8; 16],
    fencing_token: u64,
    credential_id: ProviderCredentialId,
    native: Option<
        Arc<crate::application::workspace_internal::FixtureCredentialVersionStoreFactory>,
    >,
    adapter: Arc<dyn CanonicalProviderEffect>,
) -> Result<CredentialBoundary, DaemonError> {
    let credentials = super::super::credential_versions::compose_credential_lifecycle(
        connection,
        owner,
        fencing_token,
        credential_id,
        true,
        native,
    )?;
    Ok(CredentialBoundary {
        store: credentials.store,
        readback: None,
        adapter,
        tool_adapter: None,
        status: ProviderCredentialStatus::Configured,
        enrollment_authorities: None,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: None,
        defer_initial_reconciliation: false,
    })
}

#[cfg(all(feature = "test-support", not(test)))]
pub(super) fn fixture(
    connection: ManagedConnection,
    _owner: [u8; 16],
    _fencing_token: u64,
    credential_id: ProviderCredentialId,
    adapter: Arc<dyn CanonicalProviderEffect>,
) -> Result<CredentialBoundary, DaemonError> {
    let store = super::fixture_credentials::compose(connection, credential_id)?;
    Ok(CredentialBoundary {
        store,
        readback: None,
        adapter,
        tool_adapter: None,
        status: ProviderCredentialStatus::Configured,
        enrollment_authorities: None,
        #[cfg(all(target_os = "macos", feature = "desktop-protected"))]
        credential_service: None,
        defer_initial_reconciliation: false,
    })
}
// fixture-only capability end
