#[tokio::test]
async fn maps_closed_host_errors_to_stable_redacted_http_errors() {
    let host = RecordingHost::default();
    let app = app(host.clone());

    for (sequence, error, status, code) in [
        (
            21,
            TaskRunHostError::Conflict,
            StatusCode::CONFLICT,
            "task_run_conflict",
        ),
        (
            22,
            TaskRunHostError::Backpressure,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_backpressure",
        ),
        (
            23,
            TaskRunHostError::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
        ),
        (
            24,
            TaskRunHostError::InvariantViolation,
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime_invariant_violation",
        ),
    ] {
        host.fail_next(error);
        let response = app
            .clone()
            .oneshot(command_request(
                &format!("/v1/task-runs/{TASKRUN_ID}/queue"),
                sequence,
                &format!("error-{sequence}"),
                r#"{"expectedVersion":1}"#,
            ))
            .await
            .unwrap();
        assert_error(response, status, code).await;
    }

    host.fail_next(TaskRunHostError::NotFound);
    let response = app
        .oneshot(query_request(&format!("/v1/task-runs/{TASKRUN_ID}")))
        .await
        .unwrap();
    assert_error(response, StatusCode::NOT_FOUND, "task_run_not_found").await;
}
