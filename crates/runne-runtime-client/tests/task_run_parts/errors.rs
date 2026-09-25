use super::support::*;

#[tokio::test]
async fn task_run_errors_are_redacted_and_mapped() {
    let conflict = query_task_run_result(
        409,
        "task_run_conflict",
        "{\"code\":\"task_run_conflict\",\"requestId\":\"018f2e3a-7000-7000-8000-000000000212\"}",
    )
    .await
    .expect_err("task run conflict");
    assert_eq!(conflict.kind(), RuntimeApiErrorKind::Conflict);
    assert_eq!(
        conflict.request_id(),
        Some("018f2e3a-7000-7000-8000-000000000212")
    );

    let invariant = query_task_run_result(
        500,
        "runtime_invariant_violation",
        "{\"code\":\"runtime_invariant_violation\",\"requestId\":\"018f2e3a-7000-7000-8000-000000000213\"}",
    )
    .await
    .expect_err("runtime invariant violation");
    assert_eq!(invariant.kind(), RuntimeApiErrorKind::InvalidResponse);
    assert_eq!(invariant.request_id(), None);
}
