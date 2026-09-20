#[path = "task_run_read_support/mod.rs"]
mod support;

use runne_runtime_client::{CanonicalId, RuntimeApiError, RuntimeApiErrorKind};

async fn get_task_run_error(response: support::RawResponse) -> RuntimeApiError {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let (result, _) = support::drive(
        support::session(),
        vec![response],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    result.expect_err("error response must not decode into a snapshot")
}

async fn list_task_runs_error(response: support::RawResponse) -> RuntimeApiError {
    let (result, _) = support::drive(support::session(), vec![response], |client| async move {
        client.list_task_runs().await
    })
    .await;
    result.expect_err("error response must not decode into a list")
}

#[tokio::test]
async fn task_run_read_get_401_maps_with_request_id() {
    let error = get_task_run_error(support::error_response(
        401,
        "Unauthorized",
        "unauthorized",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unauthorized);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_403_forbidden_maps_to_unauthorized() {
    let error = get_task_run_error(support::error_response(
        403,
        "Forbidden",
        "forbidden",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unauthorized);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_list_401_maps_with_request_id() {
    let error = list_task_runs_error(support::error_response(
        401,
        "Unauthorized",
        "unauthorized",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unauthorized);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_unknown_400_code_yields_invalid_response() {
    let error = get_task_run_error(support::error_response(
        400,
        "Bad Request",
        "mystery_code",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn task_run_read_get_502_yields_invalid_response_without_retry() {
    let task_run_id = CanonicalId::parse(support::TASK_RUN_ID).expect("task run ID");
    let (result, requests) = support::drive(
        support::session(),
        vec![support::error_response(
            502,
            "Bad Gateway",
            "runtime_invariant_violation",
            support::REQUEST_ID,
        )],
        move |client| async move { client.get_task_run(task_run_id).await },
    )
    .await;
    let error = result.expect_err("bad gateway must be rejected");
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
    assert_eq!(requests.len(), 1, "canonical client must not retry");
}

#[tokio::test]
async fn task_run_read_get_409_maps_with_request_id() {
    let error = get_task_run_error(support::error_response(
        409,
        "Conflict",
        "task_run_conflict",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Conflict);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_404_task_run_not_found_maps_to_not_found() {
    let error = get_task_run_error(support::error_response(
        404,
        "Not Found",
        "task_run_not_found",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::NotFound);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_400_invalid_task_run_id_maps_to_invalid_request() {
    let error = get_task_run_error(support::error_response(
        400,
        "Bad Request",
        "invalid_task_run_id",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidRequest);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_429_backpressure_maps_to_backpressure() {
    let error = get_task_run_error(support::error_response(
        429,
        "Too Many Requests",
        "runtime_backpressure",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Backpressure);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_503_unavailable_maps_to_unavailable() {
    let error = get_task_run_error(support::error_response(
        503,
        "Service Unavailable",
        "runtime_unavailable",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::Unavailable);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_413_maps_to_response_too_large() {
    let error = get_task_run_error(support::error_response(
        413,
        "Content Too Large",
        "process_output_too_large",
        support::REQUEST_ID,
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::ResponseTooLarge);
    assert_eq!(error.request_id(), Some(support::REQUEST_ID));
}

#[tokio::test]
async fn task_run_read_get_request_id_header_envelope_mismatch_yields_invalid_response() {
    let response = support::RawResponse::json(
        404,
        "Not Found",
        support::envelope_body("task_run_not_found", support::OTHER_REQUEST_ID),
    )
    .with_header("x-request-id", support::REQUEST_ID);
    let error = get_task_run_error(response).await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
}

#[tokio::test]
async fn task_run_read_get_non_uuid_request_id_yields_invalid_response() {
    let error = get_task_run_error(support::error_response(
        409,
        "Conflict",
        "task_run_conflict",
        "not-a-uuid-v7",
    ))
    .await;
    assert_eq!(error.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(error.request_id(), None);
}
