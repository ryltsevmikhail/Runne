#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{CanonicalId, RuntimeApiErrorKind};

/// Asserts the error's Display and Debug never carry response-derived canary
/// material, while the correlation identity stays available.
fn assert_redacted(error: &runne_runtime_client::RuntimeApiError) {
    let display = error.to_string();
    let debug = format!("{error:?}");
    assert!(
        !display.contains(support::CANARY),
        "display leaked: {display}"
    );
    assert!(!debug.contains(support::CANARY), "debug leaked: {debug}");
}

#[tokio::test]
async fn task_run_read_display_debug_omit_invalid_response_canary() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let body = format!("{} not json", support::CANARY);
    let (result, _) = support::drive(
        support::session(),
        vec![support::ok_json(body)],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let error = result.expect_err("malformed body must be rejected");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
    assert_redacted(&error);
}

#[tokio::test]
async fn task_run_read_display_debug_omit_unauthorized_canary() {
    let response = support::RawResponse::json(
        401,
        support::CANARY,
        support::envelope_body("unauthorized", support::REQUEST_ID),
    )
    .with_header("x-request-id", support::REQUEST_ID)
    .with_header("x-trace-canary", support::CANARY);
    let error = get_error(response).await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unauthorized);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
    assert_redacted(&error);
}

#[tokio::test]
async fn task_run_read_display_debug_omit_conflict_canary() {
    let response = support::RawResponse::json(
        409,
        support::CANARY,
        support::envelope_body("task_run_conflict", support::REQUEST_ID),
    )
    .with_header("x-request-id", support::REQUEST_ID)
    .with_header("x-trace-canary", support::CANARY);
    let error = get_error(response).await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Conflict);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
    assert_redacted(&error);
}

async fn get_error(response: support::RawResponse) -> runne_runtime_client::RuntimeApiError {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let (result, _) = support::drive(
        support::session(),
        vec![response],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    result.expect_err("error response must not decode into a snapshot")
}
