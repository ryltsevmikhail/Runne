use super::*;
use crate::ApiPrincipalId;
use runne_domain::id::{CommandId, IntegrityDigest, WorkspaceId};
use std::future::Future;

const ID_BYTES: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];

fn command_id() -> CommandId {
    CommandId::from_bytes(ID_BYTES)
}

fn receipt() -> PermissionModeChangeReceiptV1 {
    PermissionModeChangeReceiptV1 {
        command_id: command_id(),
        idempotency_key: "mode-change-1".to_owned(),
        intent_digest: IntegrityDigest::from_bytes([2; 32]),
        authorization_revision: 8,
        selected_mode: PermissionModeV1::RiskBased,
        history: PermissionModeHistoryV1 {
            selected_mode: PermissionModeV1::RiskBased,
            effective: PermissionEffectiveStateV1::NotReady {
                reason: PermissionModeNotReadyReasonV1::PresetUnavailable,
            },
            authorization_revision: 8,
            preset_version: PermissionPresetVersionV1::V1,
            managed_policy_version: 3,
            containment: None,
            network_state: PermissionNetworkStateV1::Unavailable,
            expires_at_unix_ms: None,
        },
    }
}

#[test]
fn command_status_variants_roundtrip_with_exact_wire_tags_and_fields() {
    let receipt = receipt();
    let receipt_wire = serde_json::to_value(&receipt).expect("receipt wire DTO");
    let cases = [
        (
            PermissionModeCommandStatusV2::PendingNativeConfirmation {
                command_id: command_id(),
                expires_at_unix_ms: 1_700_000_000_000,
            },
            serde_json::json!({
                "state": "pending_native_confirmation",
                "commandId": ID_BYTES,
                "expiresAtUnixMs": 1_700_000_000_000_i64,
            }),
        ),
        (
            PermissionModeCommandStatusV2::PendingReauthentication {
                command_id: command_id(),
                expires_at_unix_ms: 1_700_000_000_001,
            },
            serde_json::json!({
                "state": "pending_reauthentication",
                "commandId": ID_BYTES,
                "expiresAtUnixMs": 1_700_000_000_001_i64,
            }),
        ),
        (
            PermissionModeCommandStatusV2::Committed { receipt },
            serde_json::json!({ "state": "committed", "receipt": receipt_wire }),
        ),
        (
            PermissionModeCommandStatusV2::Cancelled {
                command_id: command_id(),
            },
            serde_json::json!({ "state": "cancelled", "commandId": ID_BYTES }),
        ),
        (
            PermissionModeCommandStatusV2::Expired {
                command_id: command_id(),
            },
            serde_json::json!({ "state": "expired", "commandId": ID_BYTES }),
        ),
        (
            PermissionModeCommandStatusV2::Invalidated {
                command_id: command_id(),
            },
            serde_json::json!({ "state": "invalidated", "commandId": ID_BYTES }),
        ),
    ];

    for (status, expected_wire) in cases {
        assert_eq!(
            serde_json::to_value(&status).expect("status wire DTO"),
            expected_wire
        );
        assert_eq!(
            serde_json::from_value::<PermissionModeCommandStatusV2>(expected_wire)
                .expect("status roundtrip"),
            status,
        );
    }
}

#[test]
fn command_status_rejects_unknown_authority_fields() {
    for field in [
        "principalId",
        "nativeProof",
        "nonce",
        "origin",
        "grant",
        "confirmed",
        "humanConfirmed",
    ] {
        let mut wire = serde_json::json!({
            "state": "pending_native_confirmation",
            "commandId": ID_BYTES,
            "expiresAtUnixMs": 1_700_000_000_000_i64,
        });
        wire[field] = serde_json::json!("forbidden");
        assert!(
            serde_json::from_value::<PermissionModeCommandStatusV2>(wire).is_err(),
            "accepted forbidden authority field {field}",
        );
    }
}

#[test]
fn mode_change_wire_request_rejects_authority_fields_for_every_mode() {
    for requested_mode in ["ask_always", "risk_based", "full_access"] {
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
            let mut wire = serde_json::json!({
                "workspaceId": ID_BYTES,
                "commandId": ID_BYTES,
                "idempotencyKey": "mode-change-test",
                "expectedAuthorizationRevision": 4,
                "requestedMode": requested_mode,
                "presetVersion": 1,
                "expiresAtUnixMs": null,
            });
            wire[field] = serde_json::json!("forbidden");
            assert!(
                serde_json::from_value::<PermissionModeChangeRequestV1>(wire).is_err(),
                "accepted {field} for requested mode {requested_mode}",
            );
        }
    }
}

struct SignatureOnlyHost;

impl PermissionModeControlHostV2 for SignatureOnlyHost {
    fn status(
        &self,
        _principal: ApiPrincipalId,
        _workspace_id: WorkspaceId,
    ) -> impl Future<Output = Result<PermissionModeStatusV1, PermissionModeHostErrorV1>> + Send
    {
        std::future::ready(Err(PermissionModeHostErrorV1::Unavailable))
    }

    fn request_mode_change(
        &self,
        _principal: ApiPrincipalId,
        _request: ValidatedPermissionModeChangeV1,
    ) -> impl Future<Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>> + Send
    {
        std::future::ready(Err(PermissionModeHostErrorV1::Unavailable))
    }

    fn command_status(
        &self,
        _principal: ApiPrincipalId,
        _workspace_id: WorkspaceId,
        _command_id: CommandId,
    ) -> impl Future<Output = Result<PermissionModeCommandStatusV2, PermissionModeHostErrorV1>> + Send
    {
        std::future::ready(Err(PermissionModeHostErrorV1::Unavailable))
    }
}

fn assert_send_future<T, F>(future: F)
where
    F: Future<Output = Result<T, PermissionModeHostErrorV1>> + Send,
{
    drop(future);
}

#[test]
fn control_v2_requires_authenticated_principal_and_send_futures() {
    fn assert_send_sync<T: Send + Sync>(_: &T) {}

    let host = SignatureOnlyHost;
    assert_send_sync(&host);
    let principal = ApiPrincipalId::new("authenticated-principal").expect("principal");
    let workspace_id = WorkspaceId::from_bytes(ID_BYTES);
    let request = PermissionModeChangeRequestV1::new(
        workspace_id,
        command_id(),
        "control-v2-test",
        4,
        PermissionModeV1::RiskBased,
        1,
        None,
    )
    .validate()
    .expect("validated request");

    assert_send_future::<PermissionModeStatusV1, _>(host.status(principal.clone(), workspace_id));
    assert_send_future::<PermissionModeCommandStatusV2, _>(
        host.request_mode_change(principal.clone(), request),
    );
    assert_send_future::<PermissionModeCommandStatusV2, _>(host.command_status(
        principal,
        workspace_id,
        command_id(),
    ));
}

#[test]
#[allow(deprecated)]
fn legacy_v1_host_signatures_remain_unchanged_scaffold() {
    type LegacySetModeSignature =
        fn(
            &dyn PermissionModeHostV1,
            ValidatedPermissionModeChangeV1,
            Option<&[u8]>,
        ) -> Result<PermissionModeChangeReceiptV1, PermissionModeHostErrorV1>;

    let _: fn(
        &dyn PermissionModeHostV1,
        WorkspaceId,
    ) -> Result<PermissionModeStatusV1, PermissionModeHostErrorV1> =
        |host, workspace_id| host.status(workspace_id);
    let _: fn(
        &dyn PermissionModeHostV1,
        ValidatedFullAccessChallengeRequestV1,
    ) -> Result<PermissionModeChallengeIssuedV1, PermissionModeHostErrorV1> =
        |host, request| host.issue_full_access_challenge(request);
    let _: LegacySetModeSignature = |host, request, proof| host.set_mode(request, proof);
}
