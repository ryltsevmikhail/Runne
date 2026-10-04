#[derive(Clone)]
struct PausedLegacyCredentialMaterializer {
    entered: std::sync::Arc<tokio::sync::Notify>,
    release: std::sync::Arc<tokio::sync::Semaphore>,
}

impl runne_provider_deepseek::DeepSeekCredentialMaterializer
    for PausedLegacyCredentialMaterializer
{
    fn materialize(
        &self,
        _: &runne_provider::CredentialDispatchCapability,
        _: runne_provider::CredentialLifecycleRevision,
        _: runne_provider::CredentialFence,
        _: [u8; 32],
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<zeroize::Zeroizing<Vec<u8>>, runne_provider_deepseek::DeepSeekCredentialError>,
    > {
        Box::pin(async { Err(runne_provider_deepseek::DeepSeekCredentialError::AccessDenied) })
    }

    fn materialize_legacy_fixture(
        &self,
        _: &runne_provider::CredentialDispatchCapability,
        _: [u8; 32],
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<zeroize::Zeroizing<Vec<u8>>, runne_provider_deepseek::DeepSeekCredentialError>,
    > {
        Box::pin(async move {
            self.entered.notify_one();
            let permit = self
                .release
                .acquire()
                .await
                .map_err(|_| runne_provider_deepseek::DeepSeekCredentialError::AccessDenied)?;
            permit.forget();
            Ok(zeroize::Zeroizing::new(b"fixture-credential".to_vec()))
        })
    }
}

impl PausedLegacyCredentialMaterializer {
    fn fixture() -> Self {
        Self {
            entered: std::sync::Arc::new(tokio::sync::Notify::new()),
            release: std::sync::Arc::new(tokio::sync::Semaphore::new(0)),
        }
    }
}

impl DurableDispatch {
    fn cancellation_target(&self) -> CancellationTarget {
        CancellationTarget {
            database_path: self.database_path.clone(),
            database_identity: self.database_identity,
            runtime_authority: self.runtime_authority.clone(),
            taskrun_id: self.taskrun_id,
        }
    }
}

struct CancellationTarget {
    database_path: std::path::PathBuf,
    database_identity: MainDatabaseIdentity,
    runtime_authority: RuntimeAuthorityId,
    taskrun_id: TaskRunId,
}

impl CancellationTarget {
    fn request_public_cancellation(&self) {
        use runne_application::commands::CancelTaskRunInput;
        use runne_application::service::TaskRunService;

        let store = StoreTransaction::open_with_connections(
            self.database_path.to_str().expect("database path"),
            open_validated_connection(&self.database_path, self.database_identity)
                .expect("cancellation writer"),
            open_validated_reader(&self.database_path, self.database_identity)
                .expect("cancellation reader"),
            self.runtime_authority.clone(),
            std::sync::Arc::new(AllowContent),
        )
        .expect("cancellation event store");
        let version = store
            .load_task_run(self.taskrun_id)
            .expect("started task run")
            .current_version;
        TaskRunService::new(
            store.clone(),
            store.clone(),
            store,
            self.runtime_authority.clone(),
        )
        .cancel_task_run(
            &context(0x36, "cancel-before-final-send"),
            CancelTaskRunInput {
                taskrun_id: self.taskrun_id,
                expected_version: version,
            },
        )
        .expect("public cancellation request");
    }
}
