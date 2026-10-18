use crate::canonical::{CanonicalId, RuntimeApiError, RuntimeApiErrorKind};
use runne_api::{
    PermissionContainmentV1, PermissionEffectiveStateV1, PermissionModeChangeReceiptV1,
    PermissionModeChangeRequestV1, PermissionModeCommandStatusV2, PermissionModeHistoryV1,
    PermissionModeStatusV1, PermissionModeV1, PermissionNetworkStateV1, PermissionPresetVersionV1,
};
use serde_json::Value;

use super::validate_projection::valid_projection;

pub(super) struct ExpectedChange {
    pub(super) workspace_id: CanonicalId,
    pub(super) command_id: CanonicalId,
    pub(super) idempotency_key: String,
    pub(super) selected_mode: PermissionModeV1,
    pub(super) expected_revision: u64,
    pub(super) preset_version: PermissionPresetVersionV1,
    pub(super) expires_at_unix_ms: Option<i64>,
}

impl ExpectedChange {
    pub(super) fn from_request(
        request: &PermissionModeChangeRequestV1,
    ) -> Result<Self, RuntimeApiError> {
        let request = request.clone().validate().map_err(|_| invalid_request())?;
        let workspace_id = CanonicalId::parse(&request.workspace_id().to_string())?;
        let command_id = CanonicalId::parse(&request.command_id().to_string())?;
        Ok(Self {
            workspace_id,
            command_id,
            idempotency_key: request.idempotency_key().as_str().to_owned(),
            selected_mode: request.requested_mode(),
            expected_revision: request.expected_authorization_revision(),
            preset_version: request.preset_version(),
            expires_at_unix_ms: request.expires_at_unix_ms(),
        })
    }
}

pub(super) fn decode_status(bytes: &[u8]) -> Result<PermissionModeStatusV1, RuntimeApiError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_response())?;
    let allowed = [
        "selectedMode",
        "effective",
        "authorizationRevision",
        "presetVersion",
        "managedPolicyVersion",
        "pendingApprovalIds",
        "containment",
        "networkState",
        "expiresAtUnixMs",
    ];
    if !only_keys(&value, &allowed) || !valid_projection(&value, true) {
        return Err(invalid_response());
    }
    let status: PermissionModeStatusV1 =
        serde_json::from_value(value).map_err(|_| invalid_response())?;
    let coherent = i64::try_from(status.authorization_revision).is_ok()
        && i64::try_from(status.managed_policy_version).is_ok()
        && status.preset_version == PermissionPresetVersionV1::V1
        && status.expires_at_unix_ms.is_none_or(|expiry| expiry > 0)
        && match &status.effective {
            PermissionEffectiveStateV1::NotReady { .. } => true,
            PermissionEffectiveStateV1::Ready {
                mode,
                preset_version,
                scope_digest,
                containment,
            } => ready_is_coherent(
                *mode,
                *preset_version,
                scope_digest.as_bytes(),
                *containment,
                status.selected_mode,
                status.containment,
                status.network_state,
            ),
        };
    coherent.then_some(status).ok_or_else(invalid_response)
}

pub(super) fn decode_command_status(
    bytes: &[u8],
    expected_command: CanonicalId,
    expected: Option<&ExpectedChange>,
) -> Result<PermissionModeCommandStatusV2, RuntimeApiError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid_response())?;
    if !valid_command_fields(&value) {
        return Err(invalid_response());
    }
    let status: PermissionModeCommandStatusV2 =
        serde_json::from_value(value).map_err(|_| invalid_response())?;
    let actual = status_command_id(&status)?;
    if actual != expected_command {
        return Err(invalid_response());
    }
    match &status {
        PermissionModeCommandStatusV2::PendingNativeConfirmation {
            expires_at_unix_ms, ..
        }
        | PermissionModeCommandStatusV2::PendingReauthentication {
            expires_at_unix_ms, ..
        } if *expires_at_unix_ms <= 0 => return Err(invalid_response()),
        PermissionModeCommandStatusV2::Committed { receipt } => {
            validate_receipt(receipt, expected)?;
        }
        _ => {}
    }
    if let Some(expected) = expected {
        if actual != expected.command_id {
            return Err(invalid_response());
        }
        if let PermissionModeCommandStatusV2::Committed { receipt } = &status {
            let next_revision = expected.expected_revision.checked_add(1);
            if receipt.idempotency_key != expected.idempotency_key
                || receipt.selected_mode != expected.selected_mode
                || Some(receipt.authorization_revision) != next_revision
                || receipt.history.preset_version != expected.preset_version
                || receipt.history.expires_at_unix_ms != expected.expires_at_unix_ms
            {
                return Err(invalid_response());
            }
        }
    }
    Ok(status)
}

fn validate_receipt(
    receipt: &PermissionModeChangeReceiptV1,
    expected: Option<&ExpectedChange>,
) -> Result<(), RuntimeApiError> {
    let history: &PermissionModeHistoryV1 = &receipt.history;
    let coherent = receipt
        .intent_digest
        .as_bytes()
        .iter()
        .any(|byte| *byte != 0)
        && receipt.authorization_revision > 0
        && i64::try_from(receipt.authorization_revision).is_ok()
        && !receipt.idempotency_key.is_empty()
        && history.selected_mode == receipt.selected_mode
        && history.authorization_revision == receipt.authorization_revision
        && history.preset_version == PermissionPresetVersionV1::V1
        && i64::try_from(history.managed_policy_version).is_ok()
        && history.expires_at_unix_ms.is_none_or(|expiry| expiry > 0)
        && match &history.effective {
            PermissionEffectiveStateV1::NotReady { .. } => true,
            PermissionEffectiveStateV1::Ready {
                mode,
                preset_version,
                scope_digest,
                containment,
            } => ready_is_coherent(
                *mode,
                *preset_version,
                scope_digest.as_bytes(),
                *containment,
                history.selected_mode,
                history.containment,
                history.network_state,
            ),
        };
    let expected_history = expected.is_none_or(|expected| {
        history.preset_version == expected.preset_version
            && history.expires_at_unix_ms == expected.expires_at_unix_ms
    });
    (coherent && expected_history)
        .then_some(())
        .ok_or_else(invalid_response)
}

fn ready_is_coherent(
    mode: PermissionModeV1,
    preset: PermissionPresetVersionV1,
    digest: &[u8; 32],
    containment: PermissionContainmentV1,
    selected: PermissionModeV1,
    projection_containment: Option<PermissionContainmentV1>,
    network: PermissionNetworkStateV1,
) -> bool {
    mode == selected
        && preset == PermissionPresetVersionV1::V1
        && digest.iter().any(|byte| *byte != 0)
        && projection_containment == Some(containment)
        && (network != PermissionNetworkStateV1::BroadSameUser
            || containment == PermissionContainmentV1::SameUserCompositeV1)
        && (mode != PermissionModeV1::FullAccess
            || (containment == PermissionContainmentV1::SameUserCompositeV1
                && network == PermissionNetworkStateV1::BroadSameUser))
}

fn status_command_id(
    status: &PermissionModeCommandStatusV2,
) -> Result<CanonicalId, RuntimeApiError> {
    let value = match status {
        PermissionModeCommandStatusV2::PendingNativeConfirmation { command_id, .. }
        | PermissionModeCommandStatusV2::PendingReauthentication { command_id, .. }
        | PermissionModeCommandStatusV2::Cancelled { command_id }
        | PermissionModeCommandStatusV2::Expired { command_id }
        | PermissionModeCommandStatusV2::Invalidated { command_id } => command_id.to_string(),
        PermissionModeCommandStatusV2::Committed { receipt } => receipt.command_id.to_string(),
    };
    CanonicalId::parse(&value).map_err(|_| invalid_response())
}

fn valid_command_fields(value: &Value) -> bool {
    let Some(state) = value.get("state").and_then(Value::as_str) else {
        return false;
    };
    match state {
        "pending_native_confirmation" | "pending_reauthentication" => {
            only_keys(value, &["state", "commandId", "expiresAtUnixMs"])
        }
        "committed" => {
            only_keys(value, &["state", "receipt"])
                && value.get("receipt").is_some_and(|receipt| {
                    only_keys(
                        receipt,
                        &[
                            "commandId",
                            "idempotencyKey",
                            "intentDigest",
                            "authorizationRevision",
                            "selectedMode",
                            "history",
                        ],
                    ) && receipt
                        .get("history")
                        .is_some_and(|history| valid_projection(history, false))
                })
        }
        "cancelled" | "expired" | "invalidated" => only_keys(value, &["state", "commandId"]),
        _ => false,
    }
}

fn only_keys(value: &Value, allowed: &[&str]) -> bool {
    value
        .as_object()
        .is_some_and(|object| object.keys().all(|key| allowed.contains(&key.as_str())))
}

const fn invalid_request() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest)
}

const fn invalid_response() -> RuntimeApiError {
    RuntimeApiError::new(RuntimeApiErrorKind::InvalidResponse)
}
