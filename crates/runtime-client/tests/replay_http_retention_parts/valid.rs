#[tokio::test]
async fn signed_retention_gap_exposes_only_a_verified_typed_baseline() {
    let error = one_response(response(&valid_body())).await;
    assert_eq!(error.kind(), ReplayClientErrorKind::RetentionGap);
    assert_eq!(
        error.recovery_disposition(),
        gocode_runtime_client::ReplayRecoveryDisposition::Fatal
    );
    let baseline = error.retention_baseline().expect("verified baseline");
    assert_eq!(baseline.principal_id(), "local-owner");
    assert_eq!(
        baseline.aggregate_kind(),
        gocode_api::ApiReplayAggregateKind::Conversation
    );
    assert_eq!(
        baseline.aggregate_id(),
        &uuid::Uuid::parse_str(AGGREGATE).unwrap().into_bytes()
    );
    assert_eq!(baseline.sequence(), 1);
    assert_eq!(baseline.retained_floor(), 2);
}

#[tokio::test]
async fn information_free_http_and_sse_gaps_cannot_require_resync() {
    rejects(response(
        &serde_json::json!({"code":"replay_retention_gap","requestId":REQUEST_ID}),
    ))
    .await;
    assert_ne!(
        gocode_runtime_client::ReplayTerminalCode::RetentionGap.recovery_disposition(),
        gocode_runtime_client::ReplayRecoveryDisposition::ResyncRequired,
    );
}
