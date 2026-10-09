use super::{
    Action, COMMAND, OTHER_COMMAND, Response, WORKSPACE, client, committed, id_bytes, pending,
    request, serve,
};
use runne_runtime_client::{CanonicalId, PermissionModeCommandStatusV2, RuntimeApiErrorKind};

#[tokio::test]
async fn lost_ack_is_unknown_and_same_id_readback_does_not_redispatch() {
    let (origin, server) = serve(vec![
        Action::Drop,
        Action::Reply(Response::json(200, committed().to_string())),
    ])
    .await;
    let client = client(&origin);
    assert_eq!(
        client
            .request_permission_mode_change(request())
            .await
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::UnknownAfterSend
    );
    assert!(matches!(
        client
            .permission_mode_command_status(
                CanonicalId::parse(WORKSPACE).unwrap(),
                CanonicalId::parse(COMMAND).unwrap(),
            )
            .await
            .unwrap(),
        PermissionModeCommandStatusV2::Committed { .. }
    ));
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].start_line.starts_with("POST /v2/workspaces/"));
    assert_eq!(
        requests[1].start_line,
        format!("GET /v2/workspaces/{WORKSPACE}/permission-mode/commands/{COMMAND} HTTP/1.1")
    );
    assert!(
        requests[1]
            .header("authorization")
            .unwrap()
            .starts_with("GocodeSession ")
    );
}

#[tokio::test]
async fn lost_ack_can_reconcile_pending_with_get_200_without_redispatch() {
    let (origin, server) = serve(vec![
        Action::Drop,
        Action::Reply(Response::json(200, pending(COMMAND))),
    ])
    .await;
    let client = client(&origin);
    assert_eq!(
        client
            .request_permission_mode_change(request())
            .await
            .unwrap_err()
            .kind(),
        RuntimeApiErrorKind::UnknownAfterSend
    );
    assert!(matches!(
        client
            .permission_mode_command_status(
                CanonicalId::parse(WORKSPACE).unwrap(),
                CanonicalId::parse(COMMAND).unwrap(),
            )
            .await
            .unwrap(),
        PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
    ));
    let requests = server.await.unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].start_line.starts_with("POST "));
    assert_eq!(
        requests[1].start_line,
        format!("GET /v2/workspaces/{WORKSPACE}/permission-mode/commands/{COMMAND} HTTP/1.1")
    );
}

#[tokio::test]
async fn command_readback_requires_exact_command_id_and_rejects_unknown_authority_fields() {
    for body in [
        pending(OTHER_COMMAND),
        serde_json::json!({
            "state":"expired",
            "commandId":id_bytes(COMMAND),
            "nativeProof":"no"
        })
        .to_string(),
    ] {
        let (origin, server) = serve(vec![Action::Reply(Response::json(200, body))]).await;
        let result = client(&origin)
            .permission_mode_command_status(
                CanonicalId::parse(WORKSPACE).unwrap(),
                CanonicalId::parse(COMMAND).unwrap(),
            )
            .await;
        assert_eq!(
            result.unwrap_err().kind(),
            RuntimeApiErrorKind::InvalidResponse
        );
        assert_eq!(server.await.unwrap().len(), 1);
    }
}

#[tokio::test]
async fn invalidated_is_a_safe_terminal_readback_state() {
    let body = serde_json::json!({
        "state": "invalidated",
        "commandId": id_bytes(COMMAND),
    })
    .to_string();
    let (origin, server) = serve(vec![Action::Reply(Response::json(200, body))]).await;
    assert!(matches!(
        client(&origin)
            .permission_mode_command_status(
                CanonicalId::parse(WORKSPACE).unwrap(),
                CanonicalId::parse(COMMAND).unwrap(),
            )
            .await
            .unwrap(),
        PermissionModeCommandStatusV2::Invalidated { .. }
    ));
    assert_eq!(server.await.unwrap().len(), 1);
}
