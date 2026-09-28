use super::*;

#[test]
fn nm11_text_only_hostile_run_restarts_and_replays_without_trust() {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "t1_text_only::text_only_child",
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
    let mut child = command.spawn().expect("launch isolated TextOnly child");
    let deadline = Instant::now() + Duration::from_secs(90);
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll TextOnly child") {
            break status;
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            let _ = child.wait();
            panic!("NM11 TextOnly child exceeded 90 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let output = child
        .wait_with_output()
        .expect("collect TextOnly child output");
    let scanner = super::t1_support::frozen_scanner();
    super::assert_absent("TextOnly child stdout", &output.stdout, &scanner);
    super::assert_absent("TextOnly child stderr", &output.stderr, &scanner);
    assert!(
        status.success(),
        "NM11 isolated child failed after frozen scans: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "launched with the exact isolated T1 fixture selector by the parent"]
async fn text_only_child() {
    let _guard = PROCESS_FAULT_AUDIT_LOCK.lock().await;
    let temporary = owner_private::tempdir();
    let session_bus_socket =
        super::t1_support::fixture_session_bus(temporary.path(), "session-bus.sock");
    let executable =
        owner_private::ControlledExecutable::copy_with_writer_from(env!("CARGO_BIN_EXE_runned"));
    let runtime_root = temporary.path().join("runtime");
    let mut supervisor = super::t1_text_only_support::start_text_only_runtime(
        executable.path(),
        &runtime_root,
        &session_bus_socket,
    );
    let client = super::t1_text_only_support::install_text_only_client(&mut supervisor).await;
    let profile_key = [0x79; 32];
    let secure =
        Arc::new(runne_secure_store::test_support::DeterministicSecureStore::new(profile_key));
    let desktop_db = temporary.path().join("desktop-profile.sqlite3");
    let core = AppCore::open_bundled_anchored(&desktop_db, secure.clone(), profile_key)
        .expect("anchored TextOnly AppCore");
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
    let initial = core
        .open_text_only_conversation()
        .await
        .expect("open TextOnly conversation");
    let conversation_id = runne_runtime_client::CanonicalId::parse(&initial.conversation_id)
        .expect("TextOnly conversation ID");
    let database = runtime_root.join("runne-daemon/event-log.db");
    super::t1_text_only_support::assert_text_only_scope(&database, conversation_id);
    super::t1_text_only_support::assert_no_project_trust_grants(&database);
    let scope = runne_runtime_client::ReplayScope::new(
        runne_runtime_client::ReplayAggregateKind::Conversation,
        conversation_id,
    );
    let mut stream = client
        .catch_up(scope, None, |delivery| {
            let decoded = format!("{:?}", delivery.event().payload());
            super::assert_absent(
                "decoded TextOnly HTTP catch-up",
                decoded.as_bytes(),
                &super::t1_support::frozen_scanner(),
            );
            Ok::<_, ()>(())
        })
        .await
        .expect("authenticated TextOnly HTTP catch-up");
    let completed = core
        .send_text_only_message("fixture input")
        .await
        .expect("TextOnly generation");
    super::t1_text_only_support::assert_fixture_response(&completed.messages);
    let scanner = super::t1_support::frozen_scanner();
    let mut saw_live_assistant = false;
    for _ in 0..16 {
        let event = tokio::time::timeout(Duration::from_secs(5), stream.next_event())
            .await
            .expect("TextOnly SSE event timeout")
            .expect("TextOnly SSE event");
        match event {
            runne_runtime_client::ReplayStreamEvent::Delivery(delivery) => {
                let decoded = format!("{:?}", delivery.event().payload());
                super::assert_absent("decoded TextOnly SSE payload", decoded.as_bytes(), &scanner);
                if let runne_runtime_client::CanonicalReplayPayload::Conversation(
                    runne_runtime_client::ConversationReplayPayload::MessageAppended {
                        role,
                        text,
                        ..
                    },
                ) = delivery.event().payload()
                {
                    super::assert_absent("TextOnly SSE message", text.as_bytes(), &scanner);
                    saw_live_assistant |= *role
                        == runne_runtime_client::ConversationMessageRole::Assistant
                        && text == "fixture response";
                }
                stream
                    .acknowledge(&delivery)
                    .await
                    .expect("acknowledge TextOnly SSE event");
            }
            runne_runtime_client::ReplayStreamEvent::Heartbeat => {}
            runne_runtime_client::ReplayStreamEvent::Terminal(_) => break,
        }
        if saw_live_assistant {
            break;
        }
    }
    assert!(
        saw_live_assistant,
        "TextOnly assistant response arrives over authenticated SSE"
    );
    super::t1_text_only_support::assert_text_only_scope(&database, conversation_id);
    super::t1_text_only_support::assert_no_project_trust_grants(&database);

    let receipt_path = runtime_root.join("fixture-provider-wire-scan-receipt.json");
    super::t1_text_only_support::assert_wire_receipt(&receipt_path);
    for message in &completed.messages {
        super::assert_absent(
            "TextOnly replayed AppCore message",
            message.text.as_bytes(),
            &scanner,
        );
    }
    super::assert_tree_absent(
        "TextOnly daemon database sinks",
        &runtime_root.join("runne-daemon"),
        &scanner,
    );
    secret_scan::assert_file_absent(&scanner, "TextOnly wire receipt", &receipt_path);
    super::t1_support::assert_profile_sqlite_absent(
        &scanner,
        "TextOnly desktop profile",
        &desktop_db,
    );
    supervisor.stop().expect("stop TextOnly runtime");
    drop(core);

    let mut restarted = super::t1_text_only_support::start_text_only_runtime(
        executable.path(),
        &runtime_root,
        &session_bus_socket,
    );
    let client = super::t1_text_only_support::install_text_only_client(&mut restarted).await;
    let reopened = AppCore::open_bundled_anchored(&desktop_db, secure, profile_key)
        .expect("reopen anchored TextOnly AppCore");
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
        .expect("resume TextOnly conversation");
    assert_eq!(replayed.conversation_id, initial.conversation_id);
    super::t1_text_only_support::assert_fixture_response(&replayed.messages);
    for message in &replayed.messages {
        super::assert_absent(
            "restarted AppCore replay message",
            message.text.as_bytes(),
            &scanner,
        );
    }
    super::t1_text_only_support::assert_text_only_scope(&database, conversation_id);
    super::t1_text_only_support::assert_no_project_trust_grants(&database);
    assert_eq!(
        std::fs::read_to_string(runtime_root.join("fixture-provider-request-count")).unwrap(),
        "1"
    );
    super::assert_tree_absent(
        "TextOnly restart replay daemon sinks",
        &runtime_root.join("runne-daemon"),
        &scanner,
    );
    secret_scan::assert_file_absent(&scanner, "TextOnly restart wire receipt", &receipt_path);
    super::t1_support::assert_profile_sqlite_absent(
        &scanner,
        "TextOnly restart profile",
        &desktop_db,
    );
    restarted.stop().expect("stop restarted TextOnly runtime");
    super::t1_support::assert_one_settled_dispatch(&database);
}
