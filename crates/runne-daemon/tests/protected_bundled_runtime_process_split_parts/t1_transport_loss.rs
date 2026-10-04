use super::*;

#[test]
fn t1_effect_start_transport_loss_is_uncertain_and_never_redispatched() {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let temporary = owner_private::tempdir();
    let barrier = temporary.path().join("barrier");
    std::fs::create_dir(&barrier).expect("owned barrier directory");
    for stage in ["stage-ready", "lease-held"] {
        std::fs::write(barrier.join(format!("{stage}.release")), b"continue")
            .expect("pre-release T1 barrier");
    }
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command.args([
        "--exact",
        "t1_transport_loss::transport_loss_child",
        "--ignored",
        "--nocapture",
    ]);
    command
        .env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1")
        .env("RUNNE_TEST_T1_TRUST_TRANSPORT_LOSS", "1")
        .env("RUNNE_TEST_T1_TRUST_BARRIER_DIR", &barrier)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("launch isolated T1 loss child");
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll loss child") {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            panic!("T1 loss child exceeded 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect loss child output");
    let scanner = super::t1_support::frozen_scanner();
    super::assert_absent("T1 loss child stdout", &output.stdout, &scanner);
    super::assert_absent("T1 loss child stderr", &output.stderr, &scanner);
    assert!(
        status.success(),
        "T1 loss child failed after frozen scans: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "launched with the exact isolated T1 transport-loss selector"]
async fn transport_loss_child() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let barrier = std::path::PathBuf::from(
        std::env::var_os("RUNNE_TEST_T1_TRUST_BARRIER_DIR").expect("barrier directory"),
    );
    let temporary = owner_private::tempdir();
    let session_bus_socket =
        super::t1_support::fixture_session_bus(temporary.path(), "session-bus.sock");
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let runtime_root = temporary.path().join("runtime");
    let mut supervisor = start_t1_runtime(executable.path(), &runtime_root, &session_bus_socket);
    let client = install_t1_client(&mut supervisor).await;
    let profile_key = [0x64; 32];
    let secure =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile_key));
    let profile_db = temporary.path().join("profile.sqlite3");
    let core =
        AppCore::open_bundled_anchored(&profile_db, secure, profile_key).expect("anchored AppCore");
    let install = core
        .begin_bundled_runtime_start()
        .await
        .expect("install lease");
    core.install_bundled_runtime_client(install, client.clone())
        .await
        .expect("install live client");
    let project_directory = temporary.path().join("project");
    std::fs::create_dir(&project_directory).expect("project directory");
    let project = core
        .open_local_project(&project_directory)
        .expect("project");
    let database = runtime_root.join("runne-daemon/event-log.db");
    prepare_canonical_conversation_workspace(&core, project, &database).await;
    let conversation = core
        .open_project_conversation(project)
        .await
        .expect("conversation");
    let conversation_id = runne_runtime_client::CanonicalId::parse(&conversation.conversation_id)
        .expect("canonical conversation");
    let command_id = runne_runtime_client::CanonicalId::now_v7();
    let request = runne_runtime_client::GenerateTextRequest::new(
        runne_runtime_client::CommandIdentity::new(command_id, command_id.to_string())
            .expect("fixed command identity"),
        conversation_id,
        conversation.stream_version,
        "fixture input",
    )
    .expect("canonical generation request");

    let first = client
        .generate_text(request.clone())
        .await
        .expect_err("lost provider reply");
    assert_eq!(
        first.kind(),
        runne_runtime_client::RuntimeApiErrorKind::OutcomeUnknown
    );
    super::t1_support::assert_uncertain_provider_effect(&database);
    assert_fixture_count(&runtime_root, "fixture-provider-request-count", "1");
    assert_fixture_count(&runtime_root, "fixture-provider-connection-count", "1");
    let receipt: serde_json::Value = serde_json::from_slice(
        &std::fs::read(runtime_root.join("fixture-provider-wire-scan-receipt.json"))
            .expect("safe wire scan receipt"),
    )
    .expect("receipt JSON");
    assert_eq!(receipt["responseSent"], false);
    assert_eq!(receipt["responseByteCount"], 0);
    assert_eq!(receipt["requestCanaryFree"], true);
    assert_eq!(receipt["responseCanaryFree"], true);
    assert!(receipt["requestByteCount"].as_u64().unwrap_or_default() > 0);
    assert!(receipt["requestByteCount"].as_u64().unwrap_or_default() > 0);

    supervisor.stop().expect("stop uncertain runtime");
    drop(core);
    drop(client);
    let revoked_revision = super::t1_support::set_project_trust_status(
        &database,
        runne_application::project_trust::ProjectTrustStatus::Untrusted,
    );
    let mut restarted = start_t1_runtime(executable.path(), &runtime_root, &session_bus_socket);
    let restarted_client = install_t1_client(&mut restarted).await;
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::Conversation,
        conversation_id,
    );
    let revoked = restarted_client
        .catch_up(scope, None, |_| Ok::<_, ()>(()))
        .await
        .err()
        .expect("revoked restart replay");
    assert_eq!(
        revoked.kind(),
        runne_runtime_client::ReplayClientErrorKind::AuthorizationRevoked
    );
    let denied = restarted_client.generate_text(request.clone()).await;
    assert_eq!(
        denied.expect_err("revoked same-command request").kind(),
        runne_runtime_client::RuntimeApiErrorKind::InvalidResponse
    );
    let trust = super::t1_support::current_project_trust(&database);
    assert_eq!(
        trust.status,
        runne_application::project_trust::ProjectTrustStatus::Untrusted
    );
    assert_eq!(trust.revision, revoked_revision);
    super::t1_support::assert_uncertain_provider_effect(&database);
    assert_fixture_count(&runtime_root, "fixture-provider-request-count", "1");
    assert_fixture_count(&runtime_root, "fixture-provider-connection-count", "1");

    super::t1_support::set_project_trust_status(
        &database,
        runne_application::project_trust::ProjectTrustStatus::Trusted,
    );
    let retried = restarted_client.generate_text(request).await;
    assert_eq!(
        retried.expect_err("uncertain same-command retry").kind(),
        runne_runtime_client::RuntimeApiErrorKind::OutcomeUnknown
    );
    assert_eq!(
        super::t1_support::current_project_trust(&database).status,
        runne_application::project_trust::ProjectTrustStatus::Trusted
    );
    super::t1_support::assert_uncertain_provider_effect(&database);
    assert_fixture_count(&runtime_root, "fixture-provider-request-count", "1");
    assert_fixture_count(&runtime_root, "fixture-provider-connection-count", "1");
    super::assert_tree_absent(
        "T1 daemon sinks after uncertainty and retry",
        &runtime_root.join("runne-daemon"),
        &super::t1_support::frozen_scanner(),
    );
    super::t1_support::assert_profile_sqlite_absent(
        &super::t1_support::frozen_scanner(),
        "T1 local profile after uncertainty and retry",
        &profile_db,
    );
    restarted.stop().expect("stop restarted runtime");
    assert!(barrier.join("lease-held.entered").is_file());
}

fn start_t1_runtime(
    executable: &std::path::Path,
    runtime_root: &std::path::Path,
    session_bus_socket: &std::path::Path,
) -> ProtectedBundledRuntimeSupervisor {
    let spec = ProtectedBundledRuntimeLaunchSpec::new(executable, runtime_root)
        .expect("T1 restart spec")
        .with_openai_provider_activation()
        .with_validated_session_bus_address(session_bus_socket)
        .expect("fixture session bus address");
    let mut supervisor =
        ProtectedBundledRuntimeSupervisor::new(DevelopmentBundledRuntimeLauncher::new(), spec);
    supervisor.start().expect("start protected T1 runtime");
    supervisor
}

async fn install_t1_client(
    supervisor: &mut ProtectedBundledRuntimeSupervisor,
) -> runne_runtime_client::AuthenticatedRuntimeClient {
    let client = supervisor
        .take_runtime_profile()
        .expect("T1 runtime profile")
        .connect(Duration::from_secs(10))
        .await
        .expect("authenticated T1 runtime client");
    supervisor
        .record_client_ready(&client)
        .expect("T1 readiness");
    client
}

fn assert_fixture_count(root: &std::path::Path, file: &str, expected: &str) {
    assert_eq!(
        std::fs::read_to_string(root.join(file)).expect("fixture count"),
        expected
    );
}
