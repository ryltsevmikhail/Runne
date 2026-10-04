use super::super::execution::SecondaryProfileRoute;
use super::super::{
    OpenAiTextProviderProfile, SharedTextProviderProfile, VerifiedSecondaryCatalog,
};
use crate::error::DaemonError;
use runne_provider::ProviderRecoveryDispatchContextProvider;
use runne_store::provider::SqliteProviderExecutionStore;
use runne_store::schema::{
    ConnectionMode, read_authority_id, read_event_log_lineage_id,
    reopen_managed_connection_validated,
};
use std::{path::Path, sync::Arc};

pub(super) struct SecondaryBackgroundConfig {
    pub(super) db_path: String,
    pub(super) execution: Arc<SqliteProviderExecutionStore>,
    pub(super) context: Arc<dyn ProviderRecoveryDispatchContextProvider>,
    pub(super) runtime_authority: [u8; 16],
    pub(super) protected_activation: bool,
    pub(super) adapter_override: Option<Arc<dyn super::super::CanonicalProviderEffect>>,
    pub(super) grant: Option<runne_store::provider::ProviderSecondaryProfileGrant>,
}

type OptionalSecondaryBackgroundRoute = (
    Option<SecondaryProfileRoute>,
    Arc<super::super::saved_remote_gate::SavedRemoteBlockingGate>,
    Option<super::service::SecondaryEffectsMetadata>,
);

pub(super) fn install_catalog_and_metadata(
    store: &SqliteProviderExecutionStore,
    launch: &runne_store::provider::ProviderRuntimeLaunchCapability,
    catalog: Option<super::super::VerifiedSecondaryCatalog>,
    db_path: &str,
    runtime_authority: [u8; 16],
    override_capabilities: Option<runne_provider::ProviderRecoveryCapabilities>,
) -> Result<
    (
        Option<runne_store::provider::ProviderSecondaryProfileGrant>,
        Option<super::service::SecondaryEffectsMetadata>,
    ),
    DaemonError,
> {
    let metadata = super::service::SecondaryEffectsMetadata::from_catalog(
        catalog.as_ref(),
        db_path,
        runtime_authority,
        1,
        override_capabilities,
    )?;
    let grant = super::install_secondary_profile_catalog(
        store,
        launch,
        catalog,
        db_path,
        runtime_authority,
    )?;
    Ok((grant, metadata))
}

pub(super) fn compose_optional_secondary_background(
    catalog: Option<&VerifiedSecondaryCatalog>,
    config: SecondaryBackgroundConfig,
    metadata: Option<super::service::SecondaryEffectsMetadata>,
) -> Result<OptionalSecondaryBackgroundRoute, DaemonError> {
    let recovery_gate = super::super::saved_remote_gate::SavedRemoteBlockingGate::new();
    if catalog.is_some() && config.grant.is_none() {
        return Ok((None, recovery_gate, metadata));
    }
    let route = catalog
        .map(|catalog| compose_secondary_background(catalog, config, Arc::clone(&recovery_gate)))
        .transpose()?;
    Ok((route, recovery_gate, metadata))
}

pub(super) fn compose_secondary_background(
    catalog: &VerifiedSecondaryCatalog,
    config: SecondaryBackgroundConfig,
    recovery_gate: Arc<super::super::saved_remote_gate::SavedRemoteBlockingGate>,
) -> Result<SecondaryProfileRoute, DaemonError> {
    let SecondaryBackgroundConfig {
        db_path,
        execution,
        context,
        runtime_authority,
        protected_activation,
        adapter_override,
        grant,
    } = config;
    let profile = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../docs/profiles/openai-responses-background-text-v1.json"
    ))
    .map_err(|_| DaemonError::Bootstrap("OpenAI background profile unavailable".into()))?;
    let connection = reopen_managed_connection_validated(
        Path::new(&db_path),
        ConnectionMode::ValidatedReopen,
        |connection| {
            if read_authority_id(connection)? != Some(runtime_authority)
                || read_event_log_lineage_id(connection)?.is_none()
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(())
        },
    )
    .map_err(|_| DaemonError::Bootstrap("OpenAI background credential store unavailable".into()))?;
    #[cfg(test)]
    let mut credentials = match adapter_override {
        Some(adapter) => super::credential_reader::fixture_enrolled(
            connection,
            runne_secure_store::ProviderCredentialId::OpenAiBackground,
            adapter,
        )?,
        None => super::credential_reader::production_background(
            connection,
            execution,
            context,
            protected_activation,
            Arc::clone(&recovery_gate),
        )?,
    };
    #[cfg(not(test))]
    let mut credentials = {
        let mut credentials = super::credential_reader::production_background(
            connection,
            execution,
            context,
            protected_activation,
            Arc::clone(&recovery_gate),
        )?;
        if let Some(adapter) = adapter_override {
            credentials.adapter = adapter;
        }
        credentials
    };
    let caps = credentials.adapter.recovery_capabilities();
    if (!caps.remote_cancel && !caps.status_check) || caps.stream_resume {
        return Err(DaemonError::Bootstrap(
            "OpenAI background recovery capabilities invalid".into(),
        ));
    }
    let credential_enrollment_control =
        super::enrollment_control::compose(&mut credentials, runtime_authority, 1)?;
    let model_id = profile.model_id().to_owned();
    let model_revision = profile.model_revision().to_owned();
    let profile = Arc::new(SharedTextProviderProfile::new(Arc::new(
        OpenAiTextProviderProfile::new(profile),
    )));
    Ok(SecondaryProfileRoute {
        profile,
        adapter: credentials.adapter,
        credential_store: credentials.store,
        credential_enrollment_control,
        credential_readback: credentials.readback,
        #[cfg(test)]
        credential_status: credentials.status,
        defer_credential_reconciliation: credentials.defer_initial_reconciliation,
        provider_id: std::borrow::Cow::Owned(catalog.spec().provider_id().to_owned()),
        model_id: std::borrow::Cow::Owned(model_id),
        model_revision: std::borrow::Cow::Owned(model_revision),
        grant,
    })
}
