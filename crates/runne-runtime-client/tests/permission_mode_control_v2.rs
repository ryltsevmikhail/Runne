#[path = "permission_mode_control_v2/readback.rs"]
mod readback;
#[path = "permission_mode_control_v2/support.rs"]
mod support;

use runne_runtime_client::{
    CanonicalId, PermissionModeChangeRequestV1, PermissionModeCommandStatusV2,
    PermissionModeStatusV1, RuntimeApiErrorKind,
};
use serde_json::{Value, json};
use support::{
    Action, COMMAND, OTHER_COMMAND, REQUEST_ID, Response, WORKSPACE, client, drive, serve,
};

const EXPIRES: i64 = 1_700_000_000_000;
const KEY: &str = "mode-change-key";

fn request() -> PermissionModeChangeRequestV1 {
    serde_json::from_value(json!({
        "workspaceId": id_bytes(WORKSPACE),
        "commandId": id_bytes(COMMAND),
        "idempotencyKey": KEY,
        "expectedAuthorizationRevision": 4,
        "requestedMode": "risk_based",
        "presetVersion": 1,
        "expiresAtUnixMs": EXPIRES,
    }))
    .unwrap()
}

fn id_bytes(value: &str) -> Vec<u8> {
    uuid::Uuid::parse_str(value).unwrap().as_bytes().to_vec()
}

fn pending(command: &str) -> String {
    json!({"state":"pending_native_confirmation","commandId":id_bytes(command),"expiresAtUnixMs":EXPIRES})
        .to_string()
}

fn committed() -> Value {
    json!({
        "state":"committed",
        "receipt":{
            "commandId":id_bytes(COMMAND),"idempotencyKey":KEY,"intentDigest":vec![1;32],
            "authorizationRevision":5,"selectedMode":"risk_based",
            "history":{
                "selectedMode":"risk_based",
                "effective":{"state":"notReady","reason":"preset_unavailable"},
                "authorizationRevision":5,"presetVersion":1,"managedPolicyVersion":1,
                "containment":null,"networkState":"unavailable","expiresAtUnixMs":EXPIRES
            }
        }
    })
}

fn ready_status() -> Value {
    json!({
        "selectedMode":"risk_based",
        "effective":{"state":"ready","mode":"risk_based","preset_version":1,"scope_digest":vec![2;32],"containment":"workspace_bound_v1"},
        "authorizationRevision":4,"presetVersion":1,"managedPolicyVersion":1,
        "pendingApprovalIds":[],"containment":"workspace_bound_v1","networkState":"brokered","expiresAtUnixMs":null
    })
}

#[tokio::test]
async fn post_uses_exact_v2_identity_and_wire_body() {
    let body = pending(COMMAND);
    let (result, requests) = drive(
        vec![Action::Reply(Response::json(202, body))],
        |client| async move { client.request_permission_mode_change(request()).await },
    )
    .await;
    assert!(matches!(
        result.unwrap(),
        PermissionModeCommandStatusV2::PendingNativeConfirmation { .. }
    ));
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].start_line,
        format!("POST /v2/workspaces/{WORKSPACE}/permission-mode HTTP/1.1")
    );
    assert!(
        requests[0]
            .header("authorization")
            .unwrap()
            .starts_with("GocodeSession ")
    );
    assert_eq!(requests[0].header("x-command-id"), Some(COMMAND));
    assert_eq!(requests[0].header("idempotency-key"), Some(KEY));
    assert_eq!(
        serde_json::from_str::<Value>(&requests[0].body).unwrap(),
        serde_json::to_value(request()).unwrap()
    );
}

#[tokio::test]
async fn malformed_or_wrong_post_ack_is_unknown_without_retry() {
    let mut wrong_revision = committed();
    wrong_revision["receipt"]["authorizationRevision"] = json!(6);
    wrong_revision["receipt"]["history"]["authorizationRevision"] = json!(6);
    let mut wrong_key = committed();
    wrong_key["receipt"]["idempotencyKey"] = json!("other-key");
    let mut wrong_mode = committed();
    wrong_mode["receipt"]["selectedMode"] = json!("ask_always");
    wrong_mode["receipt"]["history"]["selectedMode"] = json!("ask_always");
    let mut wrong_id = committed();
    wrong_id["receipt"]["commandId"] = json!(id_bytes(OTHER_COMMAND));
    let mut wrong_expiry = committed();
    wrong_expiry["receipt"]["history"]["expiresAtUnixMs"] = json!(EXPIRES + 1);
    let mut wrong_preset = committed();
    wrong_preset["receipt"]["history"]["presetVersion"] = json!(2);
    let mut zero_digest = committed();
    zero_digest["receipt"]["intentDigest"] = json!(vec![0; 32]);
    let unknown = json!({"state":"pending_native_confirmation","commandId":COMMAND,"expiresAtUnixMs":EXPIRES,"principalId":"forbidden"});
    let bodies = [
        (202, pending(OTHER_COMMAND)),
        (200, wrong_revision.to_string()),
        (200, wrong_key.to_string()),
        (200, wrong_mode.to_string()),
        (200, wrong_id.to_string()),
        (200, wrong_expiry.to_string()),
        (200, wrong_preset.to_string()),
        (200, zero_digest.to_string()),
        (200, unknown.to_string()),
    ];
    for (status, body) in bodies {
        let (result, requests) = drive(
            vec![Action::Reply(Response::json(status, body))],
            |client| async move { client.request_permission_mode_change(request()).await },
        )
        .await;
        assert_eq!(
            result.unwrap_err().kind(),
            RuntimeApiErrorKind::UnknownAfterSend
        );
        assert_eq!(requests.len(), 1);
        assert!(requests[0].start_line.starts_with("POST "));
    }
    let (result, requests) = drive(
        vec![Action::Reply(
            Response::json(200, pending(COMMAND)).truncated(1024),
        )],
        |client| async move { client.request_permission_mode_change(request()).await },
    )
    .await;
    assert_eq!(
        result.unwrap_err().kind(),
        RuntimeApiErrorKind::UnknownAfterSend
    );
    assert_eq!(requests.len(), 1);
}

#[tokio::test]
async fn unavailable_post_is_unknown_and_status_readback_rejects_bad_projection() {
    let unavailable =
        json!({"code":"permission_mode_unavailable","requestId":REQUEST_ID}).to_string();
    let (result, requests) = drive(
        vec![Action::Reply(Response::json(503, unavailable))],
        |client| async move { client.request_permission_mode_change(request()).await },
    )
    .await;
    assert_eq!(
        result.unwrap_err().kind(),
        RuntimeApiErrorKind::UnknownAfterSend
    );
    assert_eq!(requests.len(), 1);

    let status = json!({
        "selectedMode":"risk_based","effective":{"state":"notReady","reason":"preset_unavailable"},
        "authorizationRevision":4,"presetVersion":2,"managedPolicyVersion":1,
        "pendingApprovalIds":[],"containment":null,"networkState":"unavailable","expiresAtUnixMs":null
    }).to_string();
    let (result, requests) = drive(
        vec![Action::Reply(Response::json(200, status))],
        |client| async move {
            client
                .permission_mode_status(CanonicalId::parse(WORKSPACE).unwrap())
                .await
        },
    )
    .await;
    assert_eq!(
        result.unwrap_err().kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
    assert_eq!(
        requests[0].start_line,
        format!("GET /v2/workspaces/{WORKSPACE}/permission-mode HTTP/1.1")
    );
}

#[tokio::test]
async fn status_accepts_coherent_ready_state_and_rejects_zero_scope_digest() {
    let _: PermissionModeStatusV1 = serde_json::from_value(ready_status()).unwrap();
    let valid = ready_status().to_string();
    let (result, requests) = drive(
        vec![Action::Reply(Response::json(200, valid))],
        |client| async move {
            client
                .permission_mode_status(CanonicalId::parse(WORKSPACE).unwrap())
                .await
        },
    )
    .await;
    assert_eq!(result.unwrap().authorization_revision, 4);
    assert_eq!(requests.len(), 1);

    let mut invalid = ready_status();
    invalid["effective"]["scope_digest"] = json!(vec![0; 32]);
    let (result, requests) = drive(
        vec![Action::Reply(Response::json(200, invalid.to_string()))],
        |client| async move {
            client
                .permission_mode_status(CanonicalId::parse(WORKSPACE).unwrap())
                .await
        },
    )
    .await;
    assert_eq!(
        result.unwrap_err().kind(),
        RuntimeApiErrorKind::InvalidResponse
    );
    assert_eq!(requests.len(), 1);
}
