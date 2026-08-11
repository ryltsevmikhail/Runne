use super::VerifiedOwnerPrivateConfig;
use super::workspace_internal::ProtectedProviderDependencyCapsule;
use super::*;
#[cfg(all(unix, feature = "desktop-protected"))]
use crate::protected_activation::VerifiedProtectedApplicationStart;

pub(super) struct StartupProvider {
    activation: ProviderActivation,
    provenance: Option<DaemonActivationProvenance>,
    dependencies: Option<ProtectedProviderDependencyCapsule>,
    root_admission_keys: Option<gocode_api::ProtectedActivationKeys>,
}

impl StartupProvider {
    pub(super) fn deterministic(config: &ConfigurationSnapshot) -> Result<Self, DaemonError> {
        if config.provider_activation.requires_openai_execution() {
            return Err(DaemonError::Bootstrap(
                "verified provider activation provenance is unavailable".into(),
            ));
        }
        Ok(Self {
            activation: config.provider_activation.clone(),
            provenance: None,
            dependencies: None,
            root_admission_keys: None,
        })
    }

    pub(super) fn verified_external(
        config: &VerifiedOwnerPrivateConfig,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Self {
        Self {
            activation: config.provider_activation().clone(),
            provenance: Some(
                DaemonActivationProvenance::from_verified_owner_private_config(config),
            ),
            dependencies: Some(dependencies),
            root_admission_keys: None,
        }
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    pub(super) fn verified_protected(
        start: &VerifiedProtectedApplicationStart,
        keys: gocode_api::ProtectedActivationKeys,
        dependencies: ProtectedProviderDependencyCapsule,
    ) -> Self {
        Self {
            activation: start.provider_activation().clone(),
            provenance: Some(DaemonActivationProvenance::from_verified_protected_launch(
                start,
            )),
            dependencies: Some(dependencies),
            root_admission_keys: Some(keys),
        }
    }

    pub(super) fn is_protected(&self) -> bool {
        self.provenance
            .is_some_and(|provenance| provenance.is_protected())
    }

    pub(super) fn into_parts(
        self,
    ) -> (
        ProviderActivation,
        Option<DaemonActivationProvenance>,
        bool,
        Option<ProtectedProviderDependencyCapsule>,
        Option<gocode_api::ProtectedActivationKeys>,
    ) {
        let protected = self.is_protected();
        (
            self.activation,
            self.provenance,
            protected,
            self.dependencies,
            self.root_admission_keys,
        )
    }
}

impl DaemonApplication {
    pub(super) async fn start_with_bootstrap(
        config: &ConfigurationSnapshot,
        bootstrap: BootstrapOutcome,
        startup: StartupProvider,
    ) -> Result<Self, DaemonError> {
        let recovery_state = enumerate_recovery_tasks(&bootstrap.db_conn)?;
        let replay_lineage = ensure_event_log_lineage_id(&bootstrap.db_conn).map_err(|error| {
            DaemonError::Bootstrap(format!("initialize replay lineage: {error}"))
        })?;
        let replay_connection = open_runtime_connection(
            &config.db_path,
            bootstrap.authority_id,
            replay_lineage,
            "replay store",
        )?;
        let authority = RuntimeAuthorityId(hex::encode(bootstrap.authority_id));
        let secret_broker = Arc::new(Mutex::new(SecretBroker::new()));
        let prohibited_content: Arc<dyn ProhibitedContentPort> = Arc::new(
            secret_broker
                .lock()
                .map_err(|_| {
                    DaemonError::Bootstrap("initialize prohibited-content registry".to_owned())
                })?
                .prohibited_content_guard(),
        );
        let store_writer = open_runtime_connection(
            &config.db_path,
            bootstrap.authority_id,
            replay_lineage,
            "runtime writer",
        )?;
        let store_reader = open_runtime_connection(
            &config.db_path,
            bootstrap.authority_id,
            replay_lineage,
            "runtime reader",
        )?;
        store_reader
            .execute_batch("PRAGMA query_only = ON;")
            .map_err(|error| DaemonError::Bootstrap(format!("restrict runtime reader: {error}")))?;
        let store = StoreTransaction::open_with_connections(
            &config.db_path,
            store_writer,
            store_reader,
            authority.clone(),
            Arc::clone(&prohibited_content),
        )
        .map_err(|error| DaemonError::Bootstrap(format!("open runtime store: {error:?}")))?;
        let service: Arc<SqliteTaskRunService> = Arc::new(TaskRunService::new(
            store.clone(),
            store.clone(),
            store.clone(),
            authority.clone(),
        ));
        let conversation_service: Arc<SqliteConversationService> = Arc::new(
            ConversationService::new(store.clone(), store.clone(), authority.clone()),
        );
        let conversation_text_service: Arc<dyn ConversationTextCommandService> =
            Arc::new(ConversationTextService::new(
                store.clone(),
                store.clone(),
                authority,
                Arc::clone(&prohibited_content),
            ));

        let mut session_id = *uuid::Uuid::now_v7().as_bytes();
        while session_id == bootstrap.launch_identity.daemon_instance_id().into_bytes() {
            session_id = *uuid::Uuid::now_v7().as_bytes();
        }

        let (
            provider_activation,
            activation_provenance,
            protected_activation,
            dependencies,
            root_admission_keys,
        ) = startup.into_parts();
        let provider_profile_digest = *provider_activation.binding().profile_digest();
        let provider_service = match activation_provenance {
            Some(activation_provenance) => {
                compose_selected_provider(&provider_activation, || {
                    let db_path = config.db_path.clone();
                    let dispatch_connection = open_runtime_connection(
                        &db_path,
                        bootstrap.authority_id,
                        replay_lineage,
                        "provider dispatch store",
                    );
                    let execution_connection = open_runtime_connection(
                        &db_path,
                        bootstrap.authority_id,
                        replay_lineage,
                        "provider execution store",
                    );
                    let conversation_store = store.clone();
                    let conversation_service = Arc::clone(&conversation_text_service);
                    let prohibited_content = Arc::clone(&prohibited_content);
                    async move {
                        let dispatch_connection = dispatch_connection?;
                        let execution_connection = execution_connection?;
                        let dependencies = dependencies.ok_or_else(|| {
                            DaemonError::Bootstrap("provider dependencies unavailable".into())
                        })?;
                        DaemonCanonicalOpenAiService::compose(DaemonCanonicalOpenAiComposition {
                            db_path,
                            dispatch_connection,
                            execution_connection,
                            runtime_authority_id: bootstrap.authority_id,
                            runtime_generation: bootstrap.launch_generation,
                            activation_provenance,
                            expected_profile_digest: provider_profile_digest,
                            conversation_store,
                            conversation_service,
                            prohibited_content,
                            dependencies,
                        })
                        .await
                    }
                })
                .await?
            }
            None => None,
        };
        http_startup::start_http_and_runtime(
            config,
            bootstrap,
            recovery_state,
            replay_connection,
            replay_lineage,
            store,
            service,
            conversation_service,
            conversation_text_service,
            secret_broker,
            prohibited_content,
            provider_activation,
            provider_service,
            protected_activation,
            session_id,
            root_admission_keys,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_startup_constructors_keep_verified_pairing_atomic() {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(
            directory.path(),
        ));
        let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
        let verified =
            crate::application::VerifiedOwnerPrivateConfig::from_test_parts(config, bootstrap);

        let startup = StartupProvider::verified_external(
            &verified,
            ProtectedProviderDependencyCapsule::production(),
        );
        assert!(!startup.is_protected());
        assert_eq!(
            startup.activation.binding(),
            verified.provider_activation().binding()
        );
    }

    #[cfg(all(unix, feature = "desktop-protected"))]
    #[test]
    fn protected_constructor_derives_the_pair_from_one_token() {
        let directory = tempfile::tempdir().unwrap();
        let config = ConfigurationSnapshot::from_defaults(&crate::config::BuiltInDefaults::new(
            directory.path(),
        ));
        let bootstrap = crate::bootstrap::bootstrap(&config).unwrap();
        let start = VerifiedProtectedApplicationStart::from_test_parts(
            config,
            ProviderActivation::deterministic_v1(),
            bootstrap,
        );

        assert!(
            StartupProvider::verified_protected(
                &start,
                gocode_api::LaunchSecret::from_bytes([7; 32])
                    .unwrap()
                    .derive_keys(),
                ProtectedProviderDependencyCapsule::production(),
            )
            .is_protected()
        );
    }
}
