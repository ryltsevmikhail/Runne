use super::test_support::{
    ApiPrincipalId, Arc, COMMAND_BYTES, CommandId, HostCall, Mutex, OTHER_WORKSPACE_BYTES,
    ServiceExt, WORKSPACE_BYTES, WorkspaceId, app, assert_no_store, body, request, request_body,
};
use axum::http::StatusCode;

#[tokio::test]
async fn v2_routes_forward_authenticated_principal_and_return_no_store() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (app, authorization) = app(Arc::clone(&calls));
    let workspace = WorkspaceId::from_bytes(WORKSPACE_BYTES);
    let command = CommandId::from_bytes(COMMAND_BYTES);
    let status = app
        .clone()
        .oneshot(request(
            "GET",
            &format!("/v2/workspaces/{workspace}/permission-mode"),
            Some(&authorization),
            "",
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_no_store(&status).await;
    assert_eq!(body(status).await["selectedMode"], "risk_based");

    let headers = [
        ("x-command-id", command.to_string()),
        ("idempotency-key", "mode-change-key".to_owned()),
    ];
    let post = app
        .clone()
        .oneshot(request(
            "POST",
            &format!("/v2/workspaces/{workspace}/permission-mode"),
            Some(&authorization),
            &request_body(workspace, command),
            &headers,
        ))
        .await
        .unwrap();
    let post_status = post.status();
    assert_no_store(&post).await;
    let post_body = body(post).await;
    assert_eq!(post_status, StatusCode::ACCEPTED, "{post_body}");
    assert_eq!(post_body["state"], "pending_native_confirmation");

    let readback = app
        .oneshot(request(
            "GET",
            &format!("/v2/workspaces/{workspace}/permission-mode/commands/{command}"),
            Some(&authorization),
            "",
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(readback.status(), StatusCode::OK);
    assert_no_store(&readback).await;
    assert_eq!(body(readback).await["state"], "pending_reauthentication");

    let principal = ApiPrincipalId::new("local-owner").unwrap();
    assert_eq!(
        *calls.lock().unwrap(),
        vec![
            HostCall::Status(principal.clone(), workspace),
            HostCall::Request(principal.clone(), command, "mode-change-key".to_owned()),
            HostCall::CommandStatus(principal, workspace, command),
        ]
    );
}

#[tokio::test]
async fn malformed_unauthenticated_and_v1_inputs_never_reach_host() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (app, authorization) = app(Arc::clone(&calls));
    let workspace = WorkspaceId::from_bytes(WORKSPACE_BYTES);
    let command = CommandId::from_bytes(COMMAND_BYTES);
    let path = format!("/v2/workspaces/{workspace}/permission-mode");
    let valid = request_body(workspace, command);

    let unauthenticated = app
        .clone()
        .oneshot(request("GET", &path, None, "", &[]))
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
    assert_no_store(&unauthenticated).await;

    let cases = [
        (
            "POST",
            path.clone(),
            request_body(WorkspaceId::from_bytes(OTHER_WORKSPACE_BYTES), command),
            vec![
                ("x-command-id", command.to_string()),
                ("idempotency-key", "mode-change-key".into()),
            ],
        ),
        (
            "POST",
            path.clone(),
            valid.clone(),
            vec![
                ("x-command-id", "wrong".into()),
                ("idempotency-key", "mode-change-key".into()),
            ],
        ),
        (
            "POST",
            path.clone(),
            valid.clone(),
            vec![
                ("x-command-id", command.to_string()),
                ("x-command-id", command.to_string()),
                ("idempotency-key", "mode-change-key".into()),
            ],
        ),
        (
            "POST",
            path.clone(),
            valid.clone(),
            vec![("x-command-id", command.to_string())],
        ),
        (
            "POST",
            path.clone(),
            valid.clone(),
            vec![
                ("x-command-id", command.to_string()),
                ("idempotency-key", "wrong".into()),
            ],
        ),
        (
            "GET",
            "/v2/workspaces/00000000-0000-0000-0000-000000000000/permission-mode".into(),
            String::new(),
            vec![],
        ),
        (
            "GET",
            format!("{path}/commands/00000000-0000-0000-0000-000000000000"),
            String::new(),
            vec![],
        ),
    ];
    for (method, uri, body, headers) in cases {
        let response = app
            .clone()
            .oneshot(request(method, &uri, Some(&authorization), &body, &headers))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert_no_store(&response).await;
    }

    for field in [
        "nativeProof",
        "proof",
        "nonce",
        "principalId",
        "origin",
        "grant",
        "managedPolicy",
        "humanConfirmed",
    ] {
        let mut authority: serde_json::Value = serde_json::from_str(&valid).unwrap();
        authority[field] = serde_json::json!("forbidden");
        let response = app
            .clone()
            .oneshot(request(
                "POST",
                &path,
                Some(&authorization),
                &authority.to_string(),
                &[
                    ("x-command-id", command.to_string()),
                    ("idempotency-key", "mode-change-key".into()),
                ],
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{field}");
        assert_no_store(&response).await;
    }

    let response = app
        .oneshot(request(
            "GET",
            &format!("/v1/workspaces/{workspace}/permission-mode"),
            Some(&authorization),
            "",
            &[],
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_no_store(&response).await;
    assert!(calls.lock().unwrap().is_empty());
}
