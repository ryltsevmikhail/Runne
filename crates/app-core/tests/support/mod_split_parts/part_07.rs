pub struct Fixture {
    pub directory: tempfile::TempDir,
    pub database_path: std::path::PathBuf,
    pub project_id: i64,
    pub core: Arc<AppCore>,
    pub runtime: MockRuntime,
    secure: Arc<gocode_secure_store::test_support::DeterministicSecureStore>,
}

impl Fixture {
    pub async fn opened() -> Self {
        let directory = tempfile::tempdir().expect("directory");
        let database_path = directory.path().join("profile.sqlite3");
        let project_path = directory.path().join("project");
        std::fs::create_dir(&project_path).expect("project");
        let runtime = MockRuntime::start().await;
        let secure = Arc::new(
            gocode_secure_store::test_support::DeterministicSecureStore::new([0x41; 32]),
        );
        let core = Arc::new(
            AppCore::open_bundled_anchored(&database_path, secure.clone(), [0x41; 32])
                .expect("anchored bundled core"),
        );
        let lease = core
            .begin_bundled_runtime_start()
            .await
            .expect("start runtime");
        core.install_bundled_runtime_client(lease, runtime.protected_client())
            .await
            .expect("install protected runtime");
        let project_id = core
            .open_local_project(&project_path)
            .expect("open project");
        core.open_project_conversation(project_id)
            .await
            .expect("open conversation");
        Self {
            directory,
            database_path,
            project_id,
            core,
            runtime,
            secure,
        }
    }

    pub async fn reopen(&self) -> Arc<AppCore> {
        let core = Arc::new(
            AppCore::open_bundled_anchored(&self.database_path, self.secure.clone(), [0x41; 32])
                .expect("reopen anchored bundled core"),
        );
        let lease = core
            .begin_bundled_runtime_start()
            .await
            .expect("restart runtime");
        core.install_bundled_runtime_client(lease, self.runtime.protected_client())
            .await
            .expect("reinstall protected runtime");
        core
    }

    pub fn subscribe(
        &self,
        updates: Arc<Mutex<Vec<ConversationTimelineUpdate>>>,
    ) -> tokio::task::JoinHandle<Result<(), gocode_app_core::AppCoreError>> {
        let core = Arc::clone(&self.core);
        let project_id = self.project_id;
        tokio::spawn(async move {
            core.subscribe_project_conversation(project_id, move |update| {
                updates.lock().expect("updates").push(update);
            })
            .await
        })
    }
}
