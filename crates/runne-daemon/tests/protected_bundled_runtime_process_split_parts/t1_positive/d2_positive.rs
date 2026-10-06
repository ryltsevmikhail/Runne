use super::diagnostic::{count_watch_mask, open_create_watch, open_watch};
use super::*;
#[path = "d2_positive/after_results.rs"]
mod after_results;
#[path = "d2_positive/approval.rs"]
pub(super) mod approval;
#[path = "d2_positive/cancel_final.rs"]
mod cancel_final;
#[path = "d2_positive/complete.rs"]
mod complete;
#[path = "d2_positive/constants.rs"]
mod constants;
#[path = "d2_positive/crash.rs"]
pub(super) mod crash;
#[path = "d2_positive/finish_then_cancel.rs"]
mod finish_then_cancel;
#[path = "d2_positive/stale_after_result.rs"]
mod stale_after_result;
#[path = "d2_positive/stale_final.rs"]
mod stale_final;
#[path = "d2_positive/verify.rs"]
mod verify;
pub(super) use constants::*;
pub(crate) use crash::restart_same_root;

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    client: &runne_runtime_client::AuthenticatedRuntimeClient,
    conversation_id: runne_runtime_client::CanonicalId,
    workspace_id: runne_runtime_client::CanonicalId,
    project_directory: &std::path::Path,
    database: &std::path::Path,
    runtime_root: &std::path::Path,
    supervisor: &mut runne_platform_desktop::ProtectedBundledRuntimeSupervisor,
    executable: &std::path::Path,
    session_bus_socket: &std::path::Path,
) {
    eprintln!("RUN: D2 native read-create-final-stop with two public approvals");
    assert_eq!(
        std::fs::read_to_string(runtime_root.join(".runne-test-d2-scenario-selected"))
            .expect("daemon selected the forwarded D2 scenario"),
        std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO")
            .as_deref()
            .unwrap()
    );
    let read_path = project_directory.join("fixture-read.txt");
    let create_path = project_directory.join("fixture-created.txt");
    std::fs::write(&read_path, READ_BYTES).expect("seed D2 read target");
    let watch = open_watch(&read_path);
    let create_watch = open_create_watch(project_directory);
    assert!(!create_path.exists());
    let text = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .expect("pinned base profile");
    let tools = runne_provider_openai::OpenAiResponsesToolProfile::new(text)
        .expect("fixed Linux tool profile");
    let selected = runne_api::SelectedProviderProfile::new(
        runne_provider_openai::OPENAI_RESPONSES_TOOL_PROFILE_ID.to_owned(),
        tools.profile_digest(),
    )
    .expect("selected exact tool profile");
    let id = runne_runtime_client::CanonicalId::now_v7();
    let task = client
        .submit_task_run(
            runne_runtime_client::SubmitTaskRunRequest::new(
                runne_runtime_client::CommandIdentity::new(id, format!("d2-positive-{id}"))
                    .expect("D2 submit identity"),
                conversation_id,
                workspace_id,
                PROMPT,
            )
            .expect("D2 task prompt")
            .with_selected_profile(selected)
            .expect("explicit fixed tool profile"),
        )
        .await
        .expect("submit explicit D2 TaskRun")
        .task_run_id();

    let scenario = std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").unwrap_or_default();
    let first_call_creates = matches!(
        scenario.as_str(),
        "crash-after-create-effect" | "crash-before-go"
    );
    if !first_call_creates {
        verify::wait_results(database, task, 1, runtime_root).await;
        if scenario == "stale-after-result" {
            stale_after_result::exercise(
                client,
                task,
                &read_path,
                &create_path,
                &watch,
                &create_watch,
                database,
                runtime_root,
            )
            .await;
            return;
        }
        if scenario == "result-commit-crash" {
            verify::assert_encrypted_results(database, task, 1);
            assert_eq!(
                count_watch_mask(&watch, libc::IN_OPEN),
                1,
                "one auto-admitted read before result crash"
            );
            crash::after_durable_result(
                supervisor,
                executable,
                session_bus_socket,
                runtime_root,
                database,
                task,
                conversation_id,
                &read_path,
                &watch,
                &create_path,
                &create_watch,
            )
            .await;
            return;
        }
    }
    let create_approval = approval::wait_approval(client, task, None, database, runtime_root).await;
    assert_eq!(create_approval.action(), "workspace.tool.invoke");
    assert!(create_approval.resource().contains("fixture-created.txt"));
    assert!(
        create_approval
            .risk_summary()
            .contains("workspace.file.create_new")
    );
    assert!(
        !create_path.exists(),
        "Pending create has no filesystem effect"
    );
    if scenario == "deny-create" {
        approval::deny_once(client, &create_approval).await;
        let failed = verify::wait_success(client, task, database, runtime_root).await;
        assert_eq!(failed.state(), runne_runtime_client::TaskRunState::Failed);
        super::faults::assert_failure_projection(database, task);
        assert_eq!(verify::result_count(database, task), 1);
        assert_eq!(verify::reserved_effect_count(database, task), 1);
        assert_eq!(verify::release_intent_count(database, task), 1);
        assert_eq!(
            count_watch_mask(&watch, libc::IN_OPEN),
            1,
            "read was not repeated after denial"
        );
        assert_eq!(
            count_watch_mask(&create_watch, libc::IN_CREATE),
            0,
            "denied create emitted no IN_CREATE"
        );
        assert!(!create_path.exists());
        assert_eq!(
            super::diagnostic::fixture_count(runtime_root, "fixture-provider-request-count"),
            2,
            "denied create has no final provider continuation"
        );
        println!("PASS: D2 read Result followed by durable create denial without mutation");
        return;
    }
    approval::approve_twice(client, &create_approval, "create").await;
    let unlaunched_barrier = match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
        Ok("crash-approved-before-lease") => Some(("approved-before-lease", "approved")),
        Ok("crash-claimed-before-area") => Some(("claimed-before-area", "claimed")),
        _ => None,
    };
    if let Some((barrier, state)) = unlaunched_barrier {
        crash::before_unlaunched(
            Some(barrier),
            state,
            2,
            supervisor,
            executable,
            session_bus_socket,
            runtime_root,
            database,
            task,
            &read_path,
            &watch,
        )
        .await;
        return;
    }
    match std::env::var("RUNNE_TEST_D2_TOOL_SCENARIO").as_deref() {
        Ok("crash-before-go") => {
            crash::before_receipt(
                "pre-release",
                supervisor,
                executable,
                session_bus_socket,
                runtime_root,
                database,
                task,
                &create_path,
                &create_watch,
                libc::IN_CREATE,
                0,
                0,
                None,
            )
            .await;
            return;
        }
        Ok("crash-after-create-effect") => {
            crash::before_receipt(
                "after-exit",
                supervisor,
                executable,
                session_bus_socket,
                runtime_root,
                database,
                task,
                &create_path,
                &create_watch,
                libc::IN_CREATE,
                1,
                1,
                Some(CREATE_BYTES),
            )
            .await;
            return;
        }
        _ => {}
    }
    assert_eq!(verify::reserved_effect_count(database, task), 1);
    assert_eq!(verify::release_intent_count(database, task), 1);

    verify::wait_results(database, task, 2, runtime_root).await;
    assert_eq!(
        std::fs::read(&create_path).expect("native create result"),
        CREATE_BYTES
    );
    assert_eq!(
        count_watch_mask(&create_watch, libc::IN_CREATE),
        1,
        "one native create emitted one IN_CREATE event"
    );
    assert_eq!(verify::reserved_effect_count(database, task), 2);
    assert_eq!(verify::release_intent_count(database, task), 2);

    if after_results::dispatch(after_results::Fixture {
        client,
        task,
        conversation: conversation_id,
        read_path: &read_path,
        create_path: &create_path,
        read_watch: &watch,
        create_watch: &create_watch,
        database,
        runtime_root,
        supervisor,
        executable,
        session_bus_socket,
    })
    .await
    {
        return;
    }

    let completed = verify::wait_success(client, task, database, runtime_root).await;
    assert_eq!(
        completed.state(),
        runne_runtime_client::TaskRunState::Succeeded
    );
    complete::exercise(
        client,
        task,
        conversation_id,
        completed.stream_version(),
        &watch,
        &create_watch,
        database,
        runtime_root,
    )
    .await;
}
