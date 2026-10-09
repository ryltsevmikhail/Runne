use super::*;
use std::path::Path;
use std::process::{Child, Output};
use std::time::{Duration, Instant};

fn persisted_state(
    fixture: &Fixture,
    authority_id: &str,
    approval_id: ApprovalId,
) -> (runne_api::ApprovalState, u64) {
    let repository = store(fixture, authority_id);
    let runtime = tokio::runtime::Runtime::new().expect("approval read runtime");
    let summary = runtime
        .block_on(runne_api::ApprovalQueryHostPort::get_approval(
            &repository,
            runne_api::ApprovalQueryContext {
                principal: runne_api::ApiPrincipalId::new("local-owner").expect("owner principal"),
            },
            approval_id,
        ))
        .expect("read canonical approval through public Store API");
    (summary.state(), summary.request_version())
}

fn approval_arguments(fixture: &Fixture, seed: &SeededApproval) -> Vec<String> {
    vec![
        "--format".into(),
        "json".into(),
        "permissions".into(),
        "--protected-runtime-root".into(),
        fixture.root.to_string_lossy().into_owned(),
        "approvals".into(),
        "respond".into(),
        "--approval-id".into(),
        seed.approval_id.to_string(),
        "--decision".into(),
        "approve".into(),
        "--command-id".into(),
        seed.command_id.clone(),
        "--idempotency-key".into(),
        seed.idempotency_key.clone(),
    ]
}

fn approval_consent_count(fixture: &Fixture) -> usize {
    std::fs::read_to_string(&fixture.approval_mock_log)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "mock-approval-consent")
        .count()
}

fn child_output_without_barrier(
    mut child: Child,
    name: &str,
    directory: &Path,
    result_path: &Path,
) -> Output {
    let marker = directory.join(format!("ready-{name}"));
    let deadline = Instant::now() + Duration::from_mins(3);
    loop {
        if marker.exists() {
            kill_child(child);
            panic!("replay reached forbidden POST barrier {name}");
        }
        if child.try_wait().expect("poll replay CLI process").is_some() {
            return child.wait_with_output().expect("collect replay CLI output");
        }
        if Instant::now() >= deadline {
            kill_child(child);
            panic!(
                "replay CLI did not finish: {}",
                std::fs::read_to_string(result_path).unwrap_or_else(|_| "<no result>".into())
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one real protected CLI process scenario checks crash, replay, consent, and receipt"
)]
pub(super) fn run_crash_case(barrier: &str) -> (String, String) {
    let fixture = fixture();
    let (_, _, authority_id) = seed_workspace(&fixture);
    let seed = seed_approval(&fixture, &authority_id);
    let arguments = approval_arguments(&fixture, &seed);
    assert_eq!(
        persisted_state(&fixture, &authority_id, seed.approval_id),
        (runne_api::ApprovalState::Pending, 1)
    );

    let (child, result_path) = spawn_cli(&fixture, &arguments, Some(barrier));
    let cli_pid = child.id();
    let child = wait_barrier(child, barrier, &fixture.barrier_dir, &result_path);
    let daemon_pid = first_child_pid(cli_pid);
    let before_crash = permission_witness_bytes(&fixture);
    assert_eq!(before_crash.len(), 1, "one durable approval witness");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&before_crash[0])
            .expect("decode durable approval witness")["commandId"],
        seed.command_id
    );
    kill_child(child);
    assert_daemon_stops(daemon_pid);

    let committed = barrier == "approval_after_commit";
    let expected_state = if committed {
        runne_api::ApprovalState::Approved
    } else {
        runne_api::ApprovalState::Pending
    };
    let expected_version = if committed { 2 } else { 1 };
    assert_eq!(
        persisted_state(&fixture, &authority_id, seed.approval_id),
        (expected_state, expected_version),
        "canonical state matches the exact crash boundary"
    );
    assert_eq!(approval_consent_count(&fixture), 1);

    let before_replay = permission_witness_bytes(&fixture);
    assert_eq!(before_replay, before_crash, "crash preserves witness bytes");
    let (replay, replay_result) = spawn_cli(&fixture, &arguments, Some("approval_before_post"));
    let replay = child_output_without_barrier(
        replay,
        "approval_before_post",
        &fixture.barrier_dir,
        &replay_result,
    );
    let replay = result_value(&replay, &replay_result);
    assert!(
        !fixture
            .barrier_dir
            .join("ready-approval_before_post")
            .exists(),
        "saved-witness replay never enters the POST seam"
    );
    assert_eq!(
        persisted_state(&fixture, &authority_id, seed.approval_id),
        (expected_state, expected_version),
        "replay leaves canonical approval unchanged"
    );
    assert_eq!(
        permission_witness_bytes(&fixture),
        before_crash,
        "replay preserves exact durable witness bytes"
    );
    assert_eq!(
        approval_consent_count(&fixture),
        1,
        "replay asks no consent"
    );

    if committed {
        assert_eq!(replay["exitCode"], 0);
        let envelope: serde_json::Value =
            serde_json::from_str(replay["stdout"].as_str().expect("JSON stdout"))
                .expect("decode approval receipt");
        assert_eq!(envelope["schemaVersion"], 1);
        assert_eq!(envelope["ok"], true);
        assert_eq!(
            envelope["data"],
            serde_json::json!({
                "approvalId": seed.approval_id.to_string(),
                "taskRunId": seed.task_run_id.to_string(),
                "commandId": seed.command_id,
                "decision": "approve",
                "state": "approved",
                "version": expected_version,
            }),
            "replay returns the exact stored approval receipt"
        );
    } else {
        assert_eq!(replay["exitCode"], 5);
        let error: serde_json::Value =
            serde_json::from_str(replay["stderr"].as_str().expect("JSON stderr"))
                .expect("decode unknown approval outcome");
        assert_eq!(error["schemaVersion"], 1);
        assert_eq!(error["ok"], false);
        assert_eq!(error["error"]["code"], "permission_command_unknown");
        assert_eq!(
            error["error"]["message"],
            format!("permission_command_unknown command_id={}", seed.command_id)
        );
    }

    let identities = (seed.approval_id.to_string(), seed.command_id);
    std::fs::remove_dir_all(&fixture.temporary).expect("remove successful approval fixture");
    identities
}
