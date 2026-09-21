//! Live CLI tests for the read-only `task` command: the real binary talks to a
//! real in-process daemon. Seeding happens through the public runtime client
//! only (project → workspace → conversation → atomic task run submit); the
//! CLI itself stays read-only (list/get). Profile-manipulation scenarios live
//! in `task_cli_parts/profile_scenarios.rs`.

#[path = "task_cli_parts/support.rs"]
mod support;

use runne_runtime_client::{CanonicalId, TaskRunSubmitAcknowledgement};
use support::{
    connect_client, exit_code, parse_json_error_envelope, parse_typed_success_data, run_cli,
    seed_conversation, start_test_daemon, stdout_string, stop_daemon, submit_run,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_list_is_empty_on_a_fresh_daemon() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();

    let json = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "task",
        "list",
    ])
    .await;
    assert!(
        json.status.success(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    assert!(json.stderr.is_empty(), "success stderr must stay empty");
    let data = parse_typed_success_data(&json, "task list");
    assert_eq!(
        data["taskRuns"].as_array().expect("taskRuns array").len(),
        0
    );

    let text = run_cli(&["--profile", &profile_arg, "task", "list"]).await;
    assert!(text.status.success());
    assert_eq!(stdout_string(&text), "no task runs\n");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_get_of_unknown_id_is_api_error() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let unknown = CanonicalId::now_v7().to_string();

    let output = run_cli(&[
        "--format",
        "json",
        "--profile",
        &profile_arg,
        "task",
        "get",
        "--task-run-id",
        &unknown,
    ])
    .await;
    assert_eq!(exit_code(&output), 1, "not found stays in the api class");
    assert!(output.stdout.is_empty());
    let envelope = parse_json_error_envelope(&output, "task get unknown");
    assert_eq!(envelope["error"]["code"], "api_error");

    stop_daemon(&mut daemon).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn task_list_and_get_report_seeded_runs_without_pagination() {
    let mut daemon = start_test_daemon().await;
    let profile_arg = daemon.profile.to_str().expect("profile path").to_owned();
    let client = connect_client(&daemon.profile).await;
    let (conversation_id, workspace_id) = seed_conversation(&client).await;
    let ack_one = submit_run(&client, conversation_id, workspace_id).await;
    let ack_two = submit_run(&client, conversation_id, workspace_id).await;

    assert_seeded_task_list(&profile_arg, &[ack_one, ack_two]).await;
    assert_seeded_task_get(&profile_arg, ack_one).await;

    stop_daemon(&mut daemon).await;
}

/// `task list` must issue every seeded run in one response: the public API has
/// no pagination, so completeness is observable behavior, not an option.
async fn assert_seeded_task_list(profile_arg: &str, acks: &[TaskRunSubmitAcknowledgement]) {
    let list = run_cli(&["--format", "json", "--profile", profile_arg, "task", "list"]).await;
    assert!(
        list.status.success(),
        "{}",
        String::from_utf8_lossy(&list.stderr)
    );
    let data = parse_typed_success_data(&list, "task list");
    let runs = data["taskRuns"].as_array().expect("taskRuns array");
    assert_eq!(
        runs.len(),
        acks.len(),
        "the full list is issued: no pagination exists"
    );
    let mut listed_ids: Vec<String> = Vec::new();
    for run in runs {
        let id = run["taskRunId"]
            .as_str()
            .expect("taskRunId string")
            .to_owned();
        CanonicalId::parse(&id).expect("UUIDv7 task run id");
        run["state"].as_str().expect("state string");
        assert!(run["streamVersion"].as_u64().expect("numeric version") >= 1);
        assert!(
            run["activeAttemptId"].is_null() || run["activeAttemptId"].is_string(),
            "attempt is id or null"
        );
        assert!(
            run["terminalResult"].is_null() || run["terminalResult"].is_object(),
            "terminal result is object or null"
        );
        listed_ids.push(id);
    }
    for ack in acks {
        let id = ack.task_run_id().to_string();
        assert!(listed_ids.contains(&id), "seeded run {id} listed");
    }
}

/// `task get` of a freshly submitted run: the typed snapshot must mirror the
/// runtime wire contract (nonterminal state, no attempt, no terminal result),
/// and the text rendering must carry the same facts.
async fn assert_seeded_task_get(profile_arg: &str, ack: TaskRunSubmitAcknowledgement) {
    let id_one = ack.task_run_id().to_string();
    let get = run_cli(&[
        "--format",
        "json",
        "--profile",
        profile_arg,
        "task",
        "get",
        "--task-run-id",
        &id_one,
    ])
    .await;
    assert!(
        get.status.success(),
        "{}",
        String::from_utf8_lossy(&get.stderr)
    );
    let snapshot = parse_typed_success_data(&get, "task get");
    assert_eq!(snapshot["taskRunId"], id_one);
    let state = snapshot["state"].as_str().expect("state string");
    assert!(
        matches!(state, "created" | "queued"),
        "freshly submitted run is nonterminal, got {state}"
    );
    let version = snapshot["streamVersion"].as_u64().expect("numeric version");
    assert!(
        version >= ack.stream_version(),
        "snapshot version {version} must not lag the submitted ack"
    );
    assert!(
        snapshot["activeAttemptId"].is_null(),
        "created/queued carry no attempt"
    );
    assert!(
        snapshot["terminalResult"].is_null(),
        "created/queued are not terminal"
    );

    let text = run_cli(&[
        "--profile",
        profile_arg,
        "task",
        "get",
        "--task-run-id",
        &id_one,
    ])
    .await;
    assert!(text.status.success());
    let rendered = stdout_string(&text);
    assert!(
        rendered.contains(&format!("task run {id_one}")),
        "{rendered}"
    );
    assert!(rendered.contains(&format!("state: {state}")), "{rendered}");
    assert!(rendered.contains("active attempt: -"), "{rendered}");
    assert!(rendered.contains("terminal result: -"), "{rendered}");
}

#[path = "task_cli_parts/profile_scenarios.rs"]
mod profile_scenarios;
