use super::*;

#[path = "d14b_hostile/rejection.rs"]
mod rejection;

/// D1.4b negative evidence (plan 18 §T1): a headless exec-style TaskRun plus
/// resume/replay inside a hostile workspace stays text-only with zero provider
/// dispatch — instructions, skills, hooks, helpers and local MCP content never
/// reaches any sink, and no trust grant exists at any point.
#[test]
fn d14b_exec_resume_replay_stay_text_only_without_hostile_channels() {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "d14b_hostile::exec_resume_replay_child",
            "--ignored",
            "--nocapture",
        ])
        .env("RUNNE_TEST_T1_TRUST_COMPOSITION", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let mut child = command.spawn().expect("launch isolated exec child");
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll exec child") {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            panic!("D1.4b exec child exceeded 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child.wait_with_output().expect("collect exec child output");
    let scanner = super::t1_support::frozen_scanner();
    super::assert_absent("exec child stdout", &output.stdout, &scanner);
    super::assert_absent("exec child stderr", &output.stderr, &scanner);
    assert!(
        status.success(),
        "D1.4b isolated child failed after frozen scans: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "launched with the exact isolated T1 fixture selector by the parent"]
async fn exec_resume_replay_child() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let runtime_root = temporary.path().join("runtime");
    let session_bus_socket =
        super::t1_support::fixture_session_bus(temporary.path(), "session-bus.sock");
    let mut supervisor = super::t1_text_only_support::start_text_only_runtime(
        executable.path(),
        &runtime_root,
        &session_bus_socket,
    );
    let client = super::t1_text_only_support::install_text_only_client(&mut supervisor).await;
    let profile_key = [0x7b; 32];
    let secure =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile_key));
    let desktop_db = temporary.path().join("desktop-profile.sqlite3");
    let core = AppCore::open_bundled_anchored(&desktop_db, secure.clone(), profile_key)
        .expect("anchored exec AppCore");
    let lease = core
        .begin_bundled_runtime_start()
        .await
        .expect("runtime install lease");
    core.install_bundled_runtime_client(lease, client.clone())
        .await
        .expect("install authenticated protected runtime");

    let hostile_root = temporary.path().join("active-local-project");
    super::t1_support::seed_hostile_workspace(&hostile_root);
    core.open_local_project(&hostile_root)
        .expect("select hostile local project without daemon trust");
    let conversation = core
        .open_text_only_conversation()
        .await
        .expect("open TextOnly conversation for exec");
    let conversation_id = runne_runtime_client::CanonicalId::parse(&conversation.conversation_id)
        .expect("conversation ID");
    let database = runtime_root.join("runne-daemon/event-log.db");
    super::t1_text_only_support::assert_text_only_scope(&database, conversation_id);
    super::t1_text_only_support::assert_no_project_trust_grants(&database);

    // The exec run lives in real client-seeded aggregates (the protected
    // composition admits TaskRun submit only against committed roots).
    let project_id = runne_runtime_client::CanonicalId::now_v7();
    let workspace_id = runne_runtime_client::CanonicalId::now_v7();
    let exec_conversation_id = runne_runtime_client::CanonicalId::now_v7();
    let seed_identity = |label: &'static str| {
        let command_id = runne_runtime_client::CanonicalId::now_v7();
        runne_runtime_client::CommandIdentity::new(command_id, label).expect("seed identity")
    };
    client
        .create_project(
            runne_runtime_client::CreateProjectRequest::new(
                seed_identity("d14b exec project"),
                project_id,
                "d14b exec project",
            )
            .expect("project request"),
        )
        .await
        .expect("seed exec project");
    client
        .create_workspace(
            runne_runtime_client::CreateWorkspaceRequest::new(
                seed_identity("d14b exec workspace"),
                project_id,
                workspace_id,
                "d14b exec workspace",
            )
            .expect("workspace request"),
        )
        .await
        .expect("seed exec workspace");
    client
        .create_conversation(runne_runtime_client::CreateConversationRequest::new(
            seed_identity("d14b exec conversation"),
            exec_conversation_id,
            workspace_id,
            runne_api::ConversationContextScope::Workspace,
        ))
        .await
        .expect("seed exec conversation");

    let submit_identity = || {
        let command_id = runne_runtime_client::CanonicalId::now_v7();
        runne_runtime_client::CommandIdentity::new(command_id, command_id.to_string())
            .expect("command identity")
    };
    let submit = client
        .submit_task_run(
            runne_runtime_client::SubmitTaskRunRequest::new(
                submit_identity(),
                exec_conversation_id,
                workspace_id,
                "hostile exec fixture prompt",
            )
            .expect("valid exec prompt"),
        )
        .await
        .expect("atomic exec submit in hostile workspace");
    let task_run_id = submit.task_run_id();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let rejected = loop {
        let snapshot = client
            .get_task_run(task_run_id)
            .await
            .expect("read hostile TaskRun snapshot");
        if snapshot.state() == runne_runtime_client::TaskRunState::Failed {
            break snapshot;
        }
        assert_eq!(
            snapshot.state(),
            runne_runtime_client::TaskRunState::Queued,
            "hostile TextOnly execution must reject before provider dispatch"
        );
        assert!(
            tokio::time::Instant::now() < deadline,
            "worker did not reject hostile TaskRun"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(rejected.stream_version() >= 4);
    rejection::assert_taskrun_rejection_reason(&database, task_run_id);

    // Exec issued no provider effect at all.
    rejection::assert_zero_dispatch_attempts(&database);
    assert!(!runtime_root.join("fixture-provider-request-count").exists());
    assert!(
        !runtime_root
            .join("fixture-provider-wire-scan-receipt.json")
            .exists()
    );

    // Resume projection before restart: same conversation, messages only, no
    // new TaskRun, no hostile content anywhere.
    let messages = client
        .list_messages(exec_conversation_id)
        .await
        .expect("resume projection");
    let scanner = super::t1_support::frozen_scanner();
    for message in &messages.messages {
        super::assert_absent(
            "pre-restart resume message",
            message.text.as_bytes(),
            &scanner,
        );
    }
    let runs = client.list_task_runs().await.expect("resume task runs");
    assert_eq!(runs.len(), 1, "resume creates no new TaskRun");

    super::t1_text_only_support::assert_text_only_scope(&database, conversation_id);
    super::t1_text_only_support::assert_no_project_trust_grants(&database);
    super::assert_tree_absent(
        "exec daemon database sinks",
        database.parent().expect("db dir"),
        &scanner,
    );
    super::t1_support::assert_profile_sqlite_absent(&scanner, "exec desktop profile", &desktop_db);

    supervisor.stop().expect("stop exec runtime");
    drop(core);

    // Restart and replay: same conversation and run identity. The runtime-owned
    // worker may terminalize a proven pre-effect rejection, but it cannot
    // dispatch this untrusted TextOnly request or persist hostile content.
    let mut restarted = super::t1_text_only_support::start_text_only_runtime(
        executable.path(),
        &runtime_root,
        &session_bus_socket,
    );
    let client = super::t1_text_only_support::install_text_only_client(&mut restarted).await;
    let reopened = AppCore::open_bundled_anchored(&desktop_db, secure, profile_key)
        .expect("reopen anchored exec AppCore");
    let lease = reopened
        .begin_bundled_runtime_start()
        .await
        .expect("restart install lease");
    reopened
        .install_bundled_runtime_client(lease, client.clone())
        .await
        .expect("install restarted authenticated runtime");
    let replayed = reopened
        .open_text_only_conversation()
        .await
        .expect("resume exec conversation after restart");
    assert_eq!(replayed.conversation_id, conversation.conversation_id);
    let runs = client.list_task_runs().await.expect("restarted task runs");
    assert_eq!(runs.len(), 1, "restart replay creates no new TaskRun");
    assert_eq!(
        runs[0].task_run_id(),
        task_run_id,
        "the same exec run identity survives restart"
    );
    assert_eq!(
        runs[0].state(),
        runne_runtime_client::TaskRunState::Failed,
        "restart worker records the proven no-effect rejection"
    );
    rejection::assert_taskrun_rejection_reason(&database, task_run_id);

    rejection::assert_zero_dispatch_attempts(&database);
    assert!(
        !runtime_root.join("fixture-provider-request-count").exists(),
        "restart replay never dispatches the provider"
    );
    super::t1_text_only_support::assert_text_only_scope(&database, conversation_id);
    super::t1_text_only_support::assert_no_project_trust_grants(&database);
    super::assert_tree_absent(
        "restart exec daemon sinks",
        database.parent().expect("db dir"),
        &scanner,
    );
    super::t1_support::assert_profile_sqlite_absent(
        &scanner,
        "restart exec desktop profile",
        &desktop_db,
    );
    restarted.stop().expect("stop restarted exec runtime");
}
