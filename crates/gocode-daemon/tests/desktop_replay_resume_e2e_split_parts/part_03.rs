#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_unknown_schema_closes_incompatible_without_local_mutation() {
    let _process_guard = process_e2e_guard().await;
    let mut fixture = ProcessFaultFixture::open().await;
    let before = local_projection_state(&fixture.desktop_database);
    fixture.generate_text(1, "unknown-schema").await;
    fixture.stop_daemon();
    promote_conversation_event_to_unknown_schema(&fixture.daemon_database, 2);
    fixture.restart_daemon();
    let core = fixture.reopen_core().await;

    let error = core
        .open_project_conversation(fixture.project_id)
        .await
        .expect_err("unknown public schema must fail closed");

    assert_eq!(error.to_string(), "runtime_incompatible");
    assert_eq!(
        core.bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Incompatible
    );
    assert_eq!(local_projection_state(&fixture.desktop_database), before);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_session_quota_closes_reconnecting_without_local_mutation() {
    let _process_guard = process_e2e_guard().await;
    let fixture = ProcessFaultFixture::open().await;
    let before = local_projection_state(&fixture.desktop_database);
    let mut held_sessions = Vec::new();
    for _ in 0..8 {
        held_sessions.push(fixture.open_raw_live(&before.cursor).await);
    }

    let error = fixture
        .core()
        .subscribe_project_conversation(fixture.project_id, |_| {})
        .await
        .expect_err("ninth replay session must be rejected");

    assert_eq!(error.to_string(), "runtime is unavailable");
    assert_eq!(
        fixture.core().bootstrap().expect("bootstrap").runtime,
        RuntimeAvailability::Reconnecting
    );
    assert_eq!(local_projection_state(&fixture.desktop_database), before);
    drop(held_sessions);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_process_disconnected_live_consumer_closes_server_session_without_local_mutation() {
    let _process_guard = process_e2e_guard().await;
    let fixture = ProcessFaultFixture::open().await;
    let before = local_projection_state(&fixture.desktop_database);
    let mut live = fixture.open_raw_live(&before.cursor).await;
    fixture.generate_text(1, "first-live-delivery").await;
    assert!(matches!(
        live.next_event().await.expect("first live delivery"),
        ReplayStreamEvent::Delivery(_)
    ));
    drop(live);

    wait_for_closed_replay_session(&fixture.daemon_database);

    assert_eq!(local_projection_state(&fixture.desktop_database), before);
    let (last_acked, last_delivered) = closed_replay_progress(&fixture.daemon_database);
    assert_eq!(last_acked, Some(1));
    assert!(
        last_delivered.is_some_and(|position| position > 1),
        "disconnected session must close only after attempting live delivery"
    );
}

struct ProcessFaultFixture {
    child: Option<ChildDaemon>,
    _directory: tempfile::TempDir,
    daemon_database: PathBuf,
    replay_key_path: PathBuf,
    profile_path: PathBuf,
    desktop_database: PathBuf,
    next_stop_ordinal: u64,
    next_launch_generation: u64,
    core: Option<Arc<AppCore>>,
    client: Option<AuthenticatedRuntimeClient>,
    project_id: i64,
    conversation_id: CanonicalId,
}

async fn process_e2e_guard() -> MutexGuard<'static, ()> {
    PROCESS_E2E_LOCK.lock().await
}

impl ProcessFaultFixture {
    async fn open() -> Self {
        let directory = tempfile::tempdir().expect("owner-only temporary directory");
        set_owner_only(directory.path());
        let runtime_root = directory.path().join("runtime");
        let daemon_directory = runtime_root.join("gocode-daemon");
        std::fs::create_dir_all(&daemon_directory).expect("create daemon directory");
        set_owner_only(&runtime_root);
        set_owner_only(&daemon_directory);
        let daemon_database = daemon_directory.join("event-log.db");
        let replay_key_path = daemon_directory.join("replay-integrity.key");
        let profile_path = daemon_directory.join("client-profile.json");
        let first_stop = directory.path().join("fault-1.stop");
        let first_child = ChildDaemon::start(
            &daemon_database,
            &replay_key_path,
            &first_stop,
            "127.0.0.1:0",
            &profile_path,
            1,
        );
        let desktop_database = directory.path().join("desktop.sqlite3");
        let project_path = directory.path().join("project");
        std::fs::create_dir(&project_path).expect("create project");
        let core = Arc::new(
            AppCore::open_with_runtime_profile(&desktop_database, profile_path.clone())
                .expect("open desktop core"),
        );
        let project_id = core
            .open_local_project(&project_path)
            .expect("open project");
        assert_eq!(
            core.connect_runtime().await.expect("connect runtime"),
            RuntimeAvailability::Live
        );
        let snapshot = core
            .open_project_conversation(project_id)
            .await
            .expect("create conversation");
        let conversation_id =
            CanonicalId::parse(&snapshot.conversation_id).expect("canonical conversation ID");
        drop(core);
        first_child.stop();
        let second_stop = directory.path().join("fault-2.stop");
        let child = ChildDaemon::start(
            &daemon_database,
            &replay_key_path,
            &second_stop,
            "127.0.0.1:0",
            &profile_path,
            2,
        );
        let core = Arc::new(
            AppCore::open_with_runtime_profile(&desktop_database, profile_path.clone())
                .expect("reopen desktop core"),
        );
        assert_eq!(
            core.connect_runtime().await.expect("reconnect runtime"),
            RuntimeAvailability::Live
        );
        let client = authenticated_client(&profile_path).await;
        Self {
            child: Some(child),
            _directory: directory,
            daemon_database,
            replay_key_path,
            profile_path,
            desktop_database,
            next_stop_ordinal: 3,
            next_launch_generation: 3,
            core: Some(core),
            client: Some(client),
            project_id,
            conversation_id,
        }
    }

    fn stop_daemon(&mut self) {
        self.core.take();
        self.client.take();
        self.child.take().expect("running child daemon").stop();
    }

    fn restart_daemon(&mut self) {
        let minimum_generation = self.next_launch_generation;
        self.next_launch_generation += 1;
        let stop_path = self
            ._directory
            .path()
            .join(format!("fault-{}.stop", self.next_stop_ordinal));
        self.next_stop_ordinal += 1;
        self.child = Some(ChildDaemon::start(
            &self.daemon_database,
            &self.replay_key_path,
            &stop_path,
            "127.0.0.1:0",
            &self.profile_path,
            minimum_generation,
        ));
    }

    async fn reopen_core(&self) -> Arc<AppCore> {
        let core = Arc::new(
            AppCore::open_with_runtime_profile(&self.desktop_database, self.profile_path.clone())
                .expect("reopen desktop core"),
        );
        assert_eq!(
            core.connect_runtime().await.expect("reconnect runtime"),
            RuntimeAvailability::Live
        );
        core
    }

    async fn generate_text(&self, expected_version: u64, text: &str) {
        let identity =
            CommandIdentity::new(CanonicalId::now_v7(), format!("fault-{expected_version}"))
                .expect("command identity");
        let request =
            GenerateTextRequest::new(identity, self.conversation_id, expected_version, text)
                .expect("generate request");
        self.client()
            .generate_text(request)
            .await
            .expect("generate text");
    }

    async fn open_raw_live(&self, cursor: &str) -> ReplayLiveSession {
        self.client()
            .catch_up_from_persisted_cursor(
                ReplayScope::new(ReplayAggregateKind::Conversation, self.conversation_id),
                Some(cursor),
                ReplayIdentityTracker::new(),
                |_| Ok::<(), ()>(()),
                |_| {},
            )
            .await
            .expect("open raw live replay")
    }

    fn core(&self) -> &Arc<AppCore> {
        self.core.as_ref().expect("connected desktop core")
    }

    fn client(&self) -> &AuthenticatedRuntimeClient {
        self.client.as_ref().expect("connected runtime client")
    }
}

async fn authenticated_client(profile_path: &Path) -> AuthenticatedRuntimeClient {
    LocalRuntimeProfile::load(profile_path)
        .expect("strict profile v2")
        .connect(Duration::from_secs(5))
        .await
        .expect("peer-authenticated runtime client")
}
