use super::diagnostic::{count_watch_mask, diagnostic, fixture_count, open_watch, read_watch};
use super::*;
#[path = "approval_expiry.rs"]
mod approval_expiry;
#[path = "d2_faults/barriers.rs"]
mod barriers;
#[path = "d2_faults/cancellation.rs"]
mod cancellation;
#[path = "d2_faults/database.rs"]
mod database;
#[path = "d2_faults/trust_revoke.rs"]
mod trust_revoke;

pub(super) fn assert_failure_projection(
    database_path: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) {
    database::assert_failure_projection(database_path, task);
}

pub(super) fn assert_interrupted_by_restart_projection(
    database_path: &std::path::Path,
    task: runne_runtime_client::CanonicalId,
) {
    database::assert_interrupted_by_restart_projection(database_path, task);
}

const PROMPT: &str =
    "Read fixture-read.txt and create fixture-created.txt with the approved bytes.";

#[expect(
    clippy::too_many_arguments,
    reason = "Fixture plumbing keeps the exact native process, authority, barrier, and filesystem handles together."
)]
pub(super) async fn exercise(
    scenario: &str,
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
    eprintln!("RUN: D2 bounded negative scenario={scenario}");
    assert_eq!(
        std::fs::read_to_string(runtime_root.join(".runne-test-d2-scenario-selected"))
            .expect("selected D2 fault scenario"),
        scenario
    );
    let target = project_directory.join("fixture-read.txt");
    let created = project_directory.join("fixture-created.txt");
    std::fs::write(&target, b"approved fixture bytes\n").expect("seed read target");
    let watch = open_watch(&target);
    let create_watch = super::diagnostic::open_create_watch(project_directory);
    let outside = project_directory
        .parent()
        .expect("project parent")
        .join("outside-secret.txt");
    let outside_watch = if scenario == "outside-target" {
        std::fs::write(&outside, b"outside-target canary\n").expect("seed outside file");
        Some(open_watch(&outside))
    } else {
        None
    };
    let excluded = project_directory.join("id_rsa");
    let excluded_watch = if scenario == "excluded-target" {
        std::fs::write(&excluded, b"T1 excluded-path canary\n")
            .expect("seed T1-excluded file before submission");
        Some(open_watch(&excluded))
    } else {
        None
    };
    let text = runne_provider_openai::OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../../../docs/profiles/openai-responses-text-v1.json"
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
                runne_runtime_client::CommandIdentity::new(id, format!("d2-fault-{id}"))
                    .expect("D2 fault identity"),
                conversation_id,
                workspace_id,
                PROMPT,
            )
            .expect("D2 fault prompt")
            .with_selected_profile(selected)
            .expect("explicit D2 tool profile"),
        )
        .await
        .expect("submit D2 fault TaskRun")
        .task_run_id();

    match scenario {
        "deny-read" => deny_read(client, task, database, runtime_root, &watch, &created).await,
        "stale-approval" => {
            stale_approval(client, task, database, runtime_root, &watch, &created).await
        }
        "approval-expiry" => {
            approval_expiry::exercise(client, task, database, runtime_root, &watch, &created).await
        }
        "revoke-before-lease" => {
            trust_revoke::exercise(
                client,
                task,
                workspace_id,
                database,
                runtime_root,
                &watch,
                &create_watch,
                &created,
            )
            .await
        }
        "target-changed-before-go" => {
            barriers::target_changed_before_go(
                client,
                task,
                &created,
                &create_watch,
                database,
                runtime_root,
            )
            .await
        }
        "stale-after-read" => {
            barriers::target_changed_after_read_exit(
                client,
                task,
                &target,
                &watch,
                database,
                runtime_root,
            )
            .await
        }
        "cancel-before-go" => {
            cancellation::cancel_before_go(
                client,
                task,
                &created,
                &create_watch,
                database,
                runtime_root,
            )
            .await
        }
        "truncated-read-result" => {
            barriers::truncated_read_result(client, task, &watch, database, runtime_root).await
        }
        "cancel-after-create-effect" | "cancel-restart-after-create-effect" => {
            cancellation::cancel_after_create_effect(
                client,
                task,
                &created,
                &create_watch,
                database,
                runtime_root,
                supervisor,
                executable,
                session_bus_socket,
            )
            .await
        }
        "unknown-tool-proposal"
        | "malformed-tool-arguments"
        | "incomplete-provider-response"
        | "early-final-stop" => {
            let state = wait_terminal(client, task, database, runtime_root).await;
            assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
            database::assert_failure_projection(database, task);
            assert_eq!(
                fixture_count(runtime_root, "fixture-provider-request-count"),
                1
            );
            assert!(
                client
                    .list_pending_approvals()
                    .await
                    .expect("read pending approvals")
                    .into_iter()
                    .all(|row| row.task_run_id() != task),
                "invalid proposal or early stop stops before approval"
            );
            assert_eq!(read_watch(&watch), 0, "no native read without approval");
            assert_eq!(count_watch_mask(&create_watch, libc::IN_CREATE), 0);
            assert!(!created.exists(), "no native create without approval");
            assert_eq!(database::invocation_count(database, task), 0);
            assert_eq!(database::release_intent_count(database, task), 0);
            assert_eq!(database::managed_area_launch_count(database, task), 0);
            assert_eq!(database::tool_budget_effects_used(database, task), Some(0));
            println!("PASS: D2 scenario={scenario} stopped without approval or filesystem effect");
        }
        "outside-target" => {
            let state = wait_terminal(client, task, database, runtime_root).await;
            assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
            database::assert_failure_projection(database, task);
            assert_eq!(
                fixture_count(runtime_root, "fixture-provider-request-count"),
                1
            );
            assert!(
                client
                    .list_pending_approvals()
                    .await
                    .expect("pending D2 approvals")
                    .into_iter()
                    .all(|row| row.task_run_id() != task),
                "outside target is rejected before human approval"
            );
            assert_eq!(
                read_watch(&watch),
                0,
                "outside proposal never reads workspace target"
            );
            assert_eq!(
                count_watch_mask(outside_watch.as_ref().unwrap(), libc::IN_OPEN),
                0
            );
            assert_eq!(database::result_count(database, task), 0);
            assert_eq!(database::invocation_count(database, task), 0);
            assert_eq!(database::release_intent_count(database, task), 0);
            assert_eq!(database::managed_area_launch_count(database, task), 0);
            eprintln!("PASS: D2 outside-workspace proposal rejected without native helper");
        }
        "excluded-target" => {
            assert!(
                excluded.is_file(),
                "T1-excluded target was seeded before submit"
            );
            let state = flows::wait_terminal(client, task, database, runtime_root).await;
            assert_eq!(state, runne_runtime_client::TaskRunState::Failed);
            assert_eq!(
                fixture_count(runtime_root, "fixture-provider-request-count"),
                1
            );
            assert!(
                client
                    .list_pending_approvals()
                    .await
                    .expect("pending excluded-target approvals")
                    .into_iter()
                    .all(|row| row.task_run_id() != task),
                "frozen T1 exclusion is rejected before human approval"
            );
            assert_eq!(
                count_watch_mask(excluded_watch.as_ref().unwrap(), libc::IN_OPEN),
                0
            );
            assert_eq!(database::result_count(database, task), 0);
            assert_eq!(database::invocation_count(database, task), 0);
            assert_eq!(database::release_intent_count(database, task), 0);
            assert_eq!(database::managed_area_launch_count(database, task), 0);
            assert_eq!(database::tool_budget_effects_used(database, task), Some(0));
            database::assert_failure_projection(database, task);
            eprintln!("PASS: D2 T1-excluded id_rsa proposal stopped before native access");
        }
        _ => panic!("unsupported closed D2 fault scenario"),
    }
}

#[path = "d2_faults/flows.rs"]
mod flows;
pub(super) use flows::wait_terminal;
use flows::{deny_read, stale_approval};
