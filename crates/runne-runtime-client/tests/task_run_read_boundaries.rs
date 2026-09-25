//! Boundary wire evidence for the canonical `TaskRun` read API, driven through
//! the shared loopback TCP fixture and the public client only: the list count
//! limit (4096 accepted vs 4097 rejected below the HTTP byte cap) and the
//! terminal state/result invariants with byte-exact failure reasons.

#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{CanonicalId, RuntimeApiErrorKind, TaskRunState, TaskRunTerminalResult};

/// Lowest identifier suffix, adjacent to the shared fixture IDs.
const FIRST_SUFFIX: usize = 0x210;

/// Mirrors the non-exported production HTTP byte cap
/// `MAXIMUM_CANONICAL_RESPONSE_BYTES` (`src/canonical/types.rs`).
const MAXIMUM_CANONICAL_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Builds the `index`-th distinct valid `UUIDv7` identity by advancing the node
/// suffix of the shared fixture ID shape (version 7, RFC 4122 variant kept).
fn distinct_task_run_id(index: usize) -> String {
    format!("018f2e3a-7000-7000-8000-{:012x}", FIRST_SUFFIX + index)
}

/// Serializes a `taskRuns` list body of `count` distinct minimal snapshots.
fn distinct_list_body(count: usize) -> String {
    let items: Vec<String> = (0..count)
        .map(|index| support::snapshot_json(&distinct_task_run_id(index), "created", 1, None, None))
        .collect();
    support::list_json(&items)
}

/// The inclusive upper count bound accepts every one of 4096 distinct valid
/// identifiers, preserves their order, and issues exactly one list request.
#[tokio::test]
async fn task_run_read_list_4096_distinct_ids_accepted_in_order() {
    let body = distinct_list_body(4_096);
    println!("measured_list_body_bytes_4096={}", body.len());
    let (result, requests) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        |client| async move { client.list_task_runs().await },
    )
    .await;
    let snapshots = result.expect("4096 distinct identifiers must decode");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].start_line, "GET /v1/task-runs HTTP/1.1");
    assert_eq!(snapshots.len(), 4_096);
    for (index, snapshot) in snapshots.iter().enumerate() {
        let expected = CanonicalId::parse(&distinct_task_run_id(index)).expect("identity");
        assert_eq!(snapshot.task_run_id(), expected, "order at index {index}");
        assert_eq!(snapshot.state(), TaskRunState::Created);
    }
}

/// Exactly 4097 distinct valid identifiers fail as `ResponseTooLarge` with no
/// partial results and no retry. The measured serialized body stays under the
/// production HTTP byte cap, so the rejection is proven to be the 4096-item
/// count limit, not the byte limit.
#[tokio::test]
async fn task_run_read_list_4097_distinct_ids_exact_response_too_large() {
    let body = distinct_list_body(4_097);
    println!("measured_list_body_bytes_4097={}", body.len());
    assert!(
        body.len() < MAXIMUM_CANONICAL_RESPONSE_BYTES,
        "measured serialized body is {} bytes and must stay under the {} byte HTTP cap so the rejection proves the count limit",
        body.len(),
        MAXIMUM_CANONICAL_RESPONSE_BYTES
    );
    let (result, requests) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        |client| async move { client.list_task_runs().await },
    )
    .await;
    let error = result.expect_err("4097 items must fail without partial results");
    assert_eq!(requests.len(), 1);
    assert_eq!(error.kind(), RuntimeApiErrorKind::ResponseTooLarge);
    assert_eq!(error.request_id(), None);
}

/// The `succeeded` state settles with the closed `success` terminal result.
#[tokio::test]
async fn task_run_read_get_succeeded_with_success_result_accepted() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = support::snapshot_json(
        support::TASK_RUN_ID,
        "succeeded",
        9,
        None,
        Some("{\"type\":\"success\"}"),
    );
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("succeeded snapshot with success result");
    assert_eq!(snapshot.state(), TaskRunState::Succeeded);
    assert_eq!(snapshot.active_attempt_id(), None);
    assert_eq!(
        snapshot.terminal_result(),
        Some(&TaskRunTerminalResult::Success)
    );
}

/// The `failed` state settles without any terminal result.
#[tokio::test]
async fn task_run_read_get_failed_with_null_terminal_result_accepted() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = support::snapshot_json(support::TASK_RUN_ID, "failed", 7, None, None);
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("failed snapshot with null terminal result");
    assert_eq!(snapshot.state(), TaskRunState::Failed);
    assert_eq!(snapshot.stream_version(), 7);
    assert_eq!(snapshot.active_attempt_id(), None);
    assert_eq!(snapshot.terminal_result(), None);
}

/// Failure reasons survive the wire byte-for-byte: TAB, CR, LF, ESC and plain
/// multibyte Unicode pass through the production decoder without any CLI
/// escaping (Rust `String` equality compares exact UTF-8 bytes).
#[tokio::test]
async fn task_run_read_get_failure_reason_preserves_control_and_unicode_bytes() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let expected_reason = "tab\tenvelope\r\nline\u{1b}esc причина ✓";
    let body = support::snapshot_json(
        support::TASK_RUN_ID,
        "succeeded",
        11,
        None,
        Some("{\"type\":\"failure\",\"reason\":\"tab\\tenvelope\\r\\nline\\u001besc причина ✓\"}"),
    );
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let snapshot = result.expect("succeeded snapshot with preserved reason");
    assert_eq!(snapshot.state(), TaskRunState::Succeeded);
    assert_eq!(
        snapshot.terminal_result(),
        Some(&TaskRunTerminalResult::Failure {
            reason: expected_reason.to_owned()
        })
    );
}

/// Negative reproducer only: the current decoder rejects a `failed` snapshot
/// that carries a failure result. This does NOT substitute the original
/// acceptance item «Succeeded/Success Failed/Failure с reason», whose positive
/// `failed`/`Failure` form awaits the owner's criterion decision.
#[tokio::test]
async fn task_run_read_get_failed_with_failure_result_negative_reproducer() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = support::snapshot_json(
        support::TASK_RUN_ID,
        "failed",
        7,
        None,
        Some("{\"type\":\"failure\",\"reason\":\"settled\"}"),
    );
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let error = result.expect_err("failed state must reject a terminal result");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
}
