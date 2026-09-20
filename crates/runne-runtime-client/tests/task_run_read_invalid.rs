#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{CanonicalId, RuntimeApiErrorKind};

/// Asserts a snapshot GET against `body` fails as `InvalidResponse` without a
/// request correlation identity.
async fn expect_invalid_snapshot(body: String) {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let error = result.expect_err("invalid response must be rejected");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
}

/// Asserts a list GET fails with the given kind and no request identity.
async fn expect_list_kind(body: String, kind: RuntimeApiErrorKind) {
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        |client| async move { client.list_task_runs().await },
    )
    .await;
    let error = result.expect_err("invalid list response must be rejected");
    assert_eq!(error.kind(), kind);
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn task_run_read_get_malformed_json_yields_invalid_response() {
    expect_invalid_snapshot("not-json".to_owned()).await;
}

#[tokio::test]
async fn task_run_read_get_unknown_field_yields_invalid_response() {
    expect_invalid_snapshot(format!(
        "{{\"taskRunId\":\"{}\",\"state\":\"created\",\"streamVersion\":1,\"activeAttemptId\":null,\"terminalResult\":null,\"surprise\":1}}",
        support::TASK_RUN_ID
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_unknown_state_yields_invalid_response() {
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "teleporting",
        1,
        None,
        None,
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_missing_active_attempt_field_yields_invalid_response() {
    expect_invalid_snapshot(format!(
        "{{\"taskRunId\":\"{}\",\"state\":\"created\",\"streamVersion\":1,\"terminalResult\":null}}",
        support::TASK_RUN_ID
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_missing_terminal_result_field_yields_invalid_response() {
    expect_invalid_snapshot(format!(
        "{{\"taskRunId\":\"{}\",\"state\":\"created\",\"streamVersion\":1,\"activeAttemptId\":null}}",
        support::TASK_RUN_ID
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_zero_stream_version_yields_invalid_response() {
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "created",
        0,
        None,
        None,
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_state_invariant_violations_yield_invalid_response() {
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "running",
        1,
        None,
        None,
    ))
    .await;
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "succeeded",
        1,
        Some(support::ATTEMPT_ID),
        Some("{\"type\":\"success\"}"),
    ))
    .await;
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "cancelling",
        1,
        None,
        Some("{\"type\":\"success\"}"),
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_empty_failure_reason_yields_invalid_response() {
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "succeeded",
        1,
        None,
        Some("{\"type\":\"failure\",\"reason\":\"\"}"),
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_oversized_failure_reason_yields_invalid_response() {
    let reason = "x".repeat(4_097);
    expect_invalid_snapshot(support::snapshot_json(
        support::TASK_RUN_ID,
        "succeeded",
        1,
        None,
        Some(&format!("{{\"type\":\"failure\",\"reason\":\"{reason}\"}}")),
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_get_snapshot_id_mismatch_yields_invalid_response() {
    expect_invalid_snapshot(support::snapshot_json(
        support::OTHER_TASK_RUN_ID,
        "created",
        1,
        None,
        None,
    ))
    .await;
}

#[tokio::test]
async fn task_run_read_list_unknown_top_level_field_yields_invalid_response() {
    let item = support::snapshot_json(support::TASK_RUN_ID, "created", 1, None, None);
    expect_list_kind(
        format!("{{\"taskRuns\":[{item}],\"surprise\":1}}"),
        RuntimeApiErrorKind::InvalidResponse,
    )
    .await;
}

#[tokio::test]
async fn task_run_read_list_element_invalid_yields_invalid_response() {
    let valid = support::snapshot_json(support::TASK_RUN_ID, "created", 1, None, None);
    let invalid = support::snapshot_json(support::TASK_RUN_ID, "teleporting", 1, None, None);
    expect_list_kind(
        support::list_json(&[valid, invalid]),
        RuntimeApiErrorKind::InvalidResponse,
    )
    .await;
}

#[tokio::test]
async fn task_run_read_list_4097_items_yields_response_too_large() {
    let item = support::snapshot_json(support::TASK_RUN_ID, "created", 1, None, None);
    let items = vec![item; 4_097];
    expect_list_kind(
        support::list_json(&items),
        RuntimeApiErrorKind::ResponseTooLarge,
    )
    .await;
}

#[tokio::test]
async fn task_run_read_get_content_length_over_8mib_yields_response_too_large() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let (result, requests) = support::drive(
        support::session(),
        vec![support::oversized_content_length_response()],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let error = result.expect_err("oversized declared length must be rejected");
    assert_eq!(error.kind(), RuntimeApiErrorKind::ResponseTooLarge);
    assert_eq!(error.request_id(), None);
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].start_line,
        format!("GET /v1/task-runs/{} HTTP/1.1", support::TASK_RUN_ID)
    );
}
