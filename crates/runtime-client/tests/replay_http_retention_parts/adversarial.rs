#[tokio::test]
async fn all_baseline_claim_mutations_are_rejected_without_typed_baseline() {
    let cases = [
        ("schemaVersion", serde_json::json!(2)),
        ("authorityId", serde_json::json!("00".repeat(16))),
        ("principalId", serde_json::json!("other")),
        ("lineageId", serde_json::json!("00".repeat(16))),
        (
            "runtimeSessionBindingDigest",
            serde_json::json!("00".repeat(32)),
        ),
        ("replayScopeDigest", serde_json::json!("00".repeat(32))),
        ("aggregateKind", serde_json::json!("taskRun")),
        ("aggregateId", serde_json::json!("00".repeat(16))),
        ("sequence", serde_json::json!(2)),
        ("version", serde_json::json!(2)),
        ("baselineGlobalPosition", serde_json::json!(2)),
        ("projectionCodec", serde_json::json!(2)),
        ("projectionBytes", serde_json::json!("AA")),
        ("projectionBytes", serde_json::json!("!not-base64!")),
        ("projectionDigest", serde_json::json!("00".repeat(32))),
        ("retainedFloor", serde_json::json!(1)),
        ("capturedHighWater", serde_json::json!(3)),
        ("retentionGeneration", serde_json::json!(2)),
        ("retentionWitness", serde_json::json!("00".repeat(32))),
        ("issuedAtUnixMs", serde_json::json!(u64::MAX)),
        ("expiresAtUnixMs", serde_json::json!(0)),
        ("witnessMac", serde_json::json!("00".repeat(32))),
    ];
    for (claim, value) in cases {
        let mut body = valid_body();
        body["baseline"][claim] = value;
        rejects(response(&body)).await;
    }
}

#[tokio::test]
async fn malformed_headers_and_bodies_never_promote_a_retention_gap() {
    let body = serde_json::to_string(&valid_body()).unwrap();
    let header_cases = [
        format!(
            "HTTP/1.1 410 Gone\r\ncontent-type: text/plain\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
        format!(
            "HTTP/1.1 410 Gone\r\ncontent-type: application/json; charset=utf-8\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
        format!(
            "HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
        format!(
            "HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: wrong\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
        format!(
            "HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
        format!(
            "HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        ),
    ];
    for raw in header_cases {
        rejects(raw).await;
    }
    for (path, value) in [
        ("code", serde_json::json!("other")),
        (
            "requestId",
            serde_json::json!("018f2e3a-7000-7000-8000-000000000121"),
        ),
    ] {
        let mut body = valid_body();
        body[path] = value;
        rejects(response(&body)).await;
    }
}

#[tokio::test]
async fn unknown_missing_duplicate_and_oversized_responses_are_rejected() {
    for field in ["code", "requestId", "baseline"] {
        let mut body = valid_body();
        body.as_object_mut().unwrap().remove(field);
        rejects(response(&body)).await;
    }
    for field in [
        "schemaVersion",
        "authorityId",
        "principalId",
        "lineageId",
        "runtimeSessionBindingDigest",
        "replayScopeDigest",
        "aggregateKind",
        "aggregateId",
        "sequence",
        "version",
        "baselineGlobalPosition",
        "projectionCodec",
        "projectionBytes",
        "projectionDigest",
        "retainedFloor",
        "capturedHighWater",
        "retentionGeneration",
        "retentionWitness",
        "issuedAtUnixMs",
        "expiresAtUnixMs",
        "witnessMac",
    ] {
        let mut body = valid_body();
        body["baseline"].as_object_mut().unwrap().remove(field);
        rejects(response(&body)).await;
    }
    let mut unknown = valid_body();
    unknown["unexpected"] = serde_json::json!(true);
    rejects(response(&unknown)).await;
    let mut nested_unknown = valid_body();
    nested_unknown["baseline"]["unexpected"] = serde_json::json!(true);
    rejects(response(&nested_unknown)).await;
    let duplicate_top = format!(
        "{{\"code\":\"replay_retention_gap\",\"code\":\"replay_retention_gap\",\"requestId\":\"{REQUEST_ID}\",\"baseline\":{}}}",
        valid_body()["baseline"]
    );
    rejects(format!("HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{duplicate_top}", duplicate_top.len())).await;
    let duplicate_nested =
        valid_body()
            .to_string()
            .replacen("\"sequence\":1", "\"sequence\":1,\"sequence\":1", 1);
    rejects(format!("HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n{duplicate_nested}", duplicate_nested.len())).await;
    let oversized = vec![b'x'; 1024 * 1024 + 1];
    rejects(format!("HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\ncontent-length: {}\r\n\r\n", oversized.len())).await;
    let chunk = "x".repeat(1024 * 1024 + 1);
    rejects(format!("HTTP/1.1 410 Gone\r\ncontent-type: application/json\r\nx-request-id: {REQUEST_ID}\r\ntransfer-encoding: chunked\r\n\r\n{:X}\r\n{chunk}\r\n0\r\n\r\n", chunk.len())).await;
}

#[tokio::test]
async fn only_exact_410_promotes_a_verified_retention_baseline() {
    for (status, code, expected) in [
        (400, "invalid_request", ReplayClientErrorKind::InvalidRequest),
        (401, "unauthorized", ReplayClientErrorKind::AuthorizationRevoked),
        (403, "replay_sensitivity_denied", ReplayClientErrorKind::SensitivityDenied),
        (429, "replay_backpressure", ReplayClientErrorKind::Backpressure),
        (500, "runtime_invariant_violation", ReplayClientErrorKind::Integrity),
        (503, "runtime_unavailable", ReplayClientErrorKind::Transport),
    ] {
        let body = serde_json::json!({"code": code, "requestId": REQUEST_ID});
        let raw = format!(
            "HTTP/1.1 {status} Test\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.to_string().len()
        );
        assert_eq!(one_response(raw).await.kind(), expected);
    }
}

#[tokio::test]
async fn uppercase_baseline_hex_is_rejected_before_authentication() {
    let mut body = valid_body();
    body["baseline"]["authorityId"] = serde_json::json!(
        body["baseline"]["authorityId"].as_str().unwrap().to_uppercase()
    );
    rejects(response(&body)).await;
}
