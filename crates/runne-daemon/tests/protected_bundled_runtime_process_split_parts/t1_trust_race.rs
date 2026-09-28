use super::*;

#[test]
fn t1_trust_effect_lease_linearizes_both_revocation_orders() {
    run_race_child("revoke-first");
    run_race_child("lease-first");
}

fn run_race_child(mode: &str) {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let temporary = owner_private::tempdir();
    let barrier = temporary.path().join("barrier");
    std::fs::create_dir(&barrier).expect("owned barrier directory");
    if mode == "lease-first" {
        std::fs::write(barrier.join("stage-ready.release"), b"continue")
            .expect("pre-release first stage barrier");
    }
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "t1_trust_race::race_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1")
        .env("RUNNE_TEST_T1_TRUST_RACE_MODE", mode)
        .env("RUNNE_TEST_T1_TRUST_BARRIER_DIR", &barrier)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("run isolated trust-race child");
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll trust-race child") {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            panic!("trust-race child exceeded 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect trust-race output");
    let scanner = super::t1_support::frozen_scanner();
    super::assert_absent("trust-race child stdout", &output.stdout, &scanner);
    super::assert_absent("trust-race child stderr", &output.stderr, &scanner);
    assert!(
        status.success(),
        "trust-race child failed; exit status unsuccessful"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "launched with an explicit test-only fixture environment by the parent test"]
async fn race_child() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let mode = std::env::var("RUNNE_TEST_T1_TRUST_RACE_MODE").expect("race mode");
    let barrier = std::path::PathBuf::from(
        std::env::var_os("RUNNE_TEST_T1_TRUST_BARRIER_DIR").expect("owned barrier path"),
    );
    let temporary = owner_private::tempdir();
    let session_bus_socket =
        super::t1_support::fixture_session_bus(temporary.path(), "session-bus.sock");
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let runtime_root = temporary.path().join("runtime");
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable.path(), &runtime_root)
        .expect("protected race launch spec")
        .with_openai_provider_activation()
        .with_validated_session_bus_address(&session_bus_socket)
        .expect("fixture session bus address");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor.start().expect("start protected race runtime");
    let client = supervisor
        .take_runtime_profile()
        .expect("protected profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("authenticated client");
    supervisor
        .record_client_ready(&client)
        .expect("protected readiness");
    let profile_key = [0x53; 32];
    let core = AppCore::open_bundled_anchored(
        &temporary.path().join("profile.sqlite3"),
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile_key)),
        profile_key,
    )
    .expect("AppCore");
    let install = core
        .begin_bundled_runtime_start()
        .await
        .expect("begin client install");
    core.install_bundled_runtime_client(install, client)
        .await
        .expect("install client");
    let project_directory = temporary.path().join("project");
    std::fs::create_dir(&project_directory).expect("project directory");
    let project = core
        .open_local_project(&project_directory)
        .expect("local project");
    let database = runtime_root.join("runne-daemon/event-log.db");
    prepare_canonical_conversation_workspace(&core, project, &database).await;
    let stage = if mode == "revoke-first" {
        "stage-ready"
    } else {
        "lease-held"
    };
    let send = core.send_project_message(project, "fixture input");
    tokio::pin!(send);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if barrier.join(format!("{stage}.entered")).exists() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "stage barrier timeout"
        );
        tokio::select! {
            result = &mut send => panic!("send ended before stage barrier: {result:?}"),
            _ = tokio::time::sleep(Duration::from_millis(5)) => {}
        }
    }
    let release = barrier.join(format!("{stage}.release"));
    if mode == "revoke-first" {
        super::t1_support::set_project_trust_status(
            &database,
            runne_application::project_trust::ProjectTrustStatus::Untrusted,
        );
        std::fs::write(&release, b"continue").expect("release pre-lease barrier");
        assert!(
            send.await.is_err(),
            "revocation before lease must deny effect"
        );
        assert!(
            !runtime_root
                .join("fixture-provider-connection-count")
                .exists()
        );
        assert_pre_effect_rejection(&database);
    } else {
        let revoke_database = database.clone();
        let started = barrier.join("revoke-started");
        let done = barrier.join("revoke-done");
        let revoke = std::thread::spawn(move || {
            std::fs::write(started, b"started").expect("record revoker start");
            super::t1_support::set_project_trust_status(
                &revoke_database,
                runne_application::project_trust::ProjectTrustStatus::Untrusted,
            );
            std::fs::write(done, b"done").expect("record revoker completion");
        });
        let started_at = tokio::time::Instant::now() + Duration::from_secs(10);
        while !barrier.join("revoke-started").exists() {
            assert!(
                tokio::time::Instant::now() < started_at,
                "revoker start timeout"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let trust_sidecar = database.with_extension("db.project-trust");
        let probe =
            rusqlite::Connection::open(&trust_sidecar).expect("open lease contention probe");
        probe
            .busy_timeout(Duration::ZERO)
            .expect("nonblocking lease contention probe");
        let contention = probe
            .execute_batch("BEGIN IMMEDIATE")
            .expect_err("lease writer fence");
        assert!(matches!(
            contention,
            rusqlite::Error::SqliteFailure(ref failure, _)
                if matches!(failure.code, rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked)
        ));
        drop(probe);
        std::fs::write(&release, b"continue").expect("release leased barrier");
        let _delivery = send.await;
        revoke.join().expect("revocation thread");
        assert_eq!(
            std::fs::read_to_string(runtime_root.join("fixture-provider-connection-count"))
                .unwrap(),
            "1"
        );
        super::t1_support::assert_one_settled_dispatch(&database);
    }
    supervisor.stop().expect("stop race runtime");
}

fn dispatch_state_counts(database: &std::path::Path) -> (i64, i64, i64, i64) {
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read durable race state");
    let attempts: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts",
            [],
            |row| row.get(0),
        )
        .expect("count dispatch attempts");
    let settled: i64 = connection
        .query_row(
            "SELECT COUNT(*) FROM provider_dispatch_attempts attempt
             JOIN provider_terminal_outbox outbox ON outbox.dispatch_attempt_id = attempt.attempt_id
             JOIN provider_accounting_settlements accounting ON accounting.dispatch_attempt_id = attempt.attempt_id
             WHERE attempt.state = 5 AND outbox.state = 2
               AND attempt.settlement_digest = outbox.settlement_digest
               AND outbox.settlement_digest = accounting.settlement_digest
               AND length(attempt.settlement_digest) = 32",
            [],
            |row| row.get(0),
        )
        .expect("count settled race effects");
    let effects: i64 = connection
        .query_row("SELECT COUNT(*) FROM provider_effect_starts", [], |row| {
            row.get(0)
        })
        .expect("count effect starts");
    let outbox: i64 = connection
        .query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |row| {
            row.get(0)
        })
        .expect("count terminal outbox");
    (attempts, effects, outbox, settled)
}

fn assert_pre_effect_rejection(database: &std::path::Path) {
    assert_eq!(dispatch_state_counts(database), (1, 0, 0, 0));
    let connection = rusqlite::Connection::open_with_flags(
        database,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .expect("read rejected dispatch state");
    let evidence: (i64, Option<i64>) = connection
        .query_row(
            "SELECT state, pre_effect_rejection FROM provider_dispatch_attempts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read pre-effect rejection receipt");
    assert_eq!(
        evidence,
        (2, Some(7)),
        "adapter fence must reject before effect start"
    );
}
