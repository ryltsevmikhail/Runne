//! Purpose-bound full-access challenge request. The nonce never leaves the Store.

use runne_domain::id::{CommandId, IdempotencyKey, WorkspaceId, validate_uuid_v7_bytes};
use serde::{Deserialize, Serialize};

use super::{PermissionModeHostErrorV1, PermissionPresetVersionV1};

/// Caller identity for a fresh full-access challenge. Ingress supplies principal.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FullAccessChallengeRequestV1 {
    workspace_id: WorkspaceId,
    command_id: CommandId,
    idempotency_key: String,
    expected_authorization_revision: u64,
    preset_version: u16,
    expires_at_unix_ms: Option<i64>,
}

impl FullAccessChallengeRequestV1 {
    /// Builds a challenge request from caller-selected command identity only.
    pub fn new(
        workspace_id: WorkspaceId,
        command_id: CommandId,
        idempotency_key: impl Into<String>,
        expected_authorization_revision: u64,
        preset_version: u16,
        expires_at_unix_ms: Option<i64>,
    ) -> Self {
        Self {
            workspace_id,
            command_id,
            idempotency_key: idempotency_key.into(),
            expected_authorization_revision,
            preset_version,
            expires_at_unix_ms,
        }
    }

    /// Rejects malformed identifiers and unimplemented preset versions.
    pub fn validate(
        self,
    ) -> Result<ValidatedFullAccessChallengeRequestV1, PermissionModeHostErrorV1> {
        if validate_uuid_v7_bytes(self.workspace_id.as_bytes()).is_err()
            || validate_uuid_v7_bytes(self.command_id.as_bytes()).is_err()
            || self.expected_authorization_revision > i64::MAX as u64
            || self.expires_at_unix_ms.is_some_and(|expiry| expiry <= 0)
        {
            return Err(PermissionModeHostErrorV1::InvariantViolation);
        }
        let idempotency_key = IdempotencyKey::new(self.idempotency_key)
            .map_err(|_| PermissionModeHostErrorV1::InvariantViolation)?;
        let preset_version = PermissionPresetVersionV1::from_u16(self.preset_version)
            .ok_or(PermissionModeHostErrorV1::UnsupportedPresetVersion)?;
        Ok(ValidatedFullAccessChallengeRequestV1 {
            workspace_id: self.workspace_id,
            command_id: self.command_id,
            idempotency_key,
            expected_authorization_revision: self.expected_authorization_revision,
            preset_version,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }
}

/// Validated challenge request. It still contains no nonce or proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedFullAccessChallengeRequestV1 {
    workspace_id: WorkspaceId,
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    expected_authorization_revision: u64,
    preset_version: PermissionPresetVersionV1,
    expires_at_unix_ms: Option<i64>,
}

impl ValidatedFullAccessChallengeRequestV1 {
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }
    #[must_use]
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }
    #[must_use]
    pub fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    #[must_use]
    pub const fn expected_authorization_revision(&self) -> u64 {
        self.expected_authorization_revision
    }
    #[must_use]
    pub const fn preset_version(&self) -> PermissionPresetVersionV1 {
        self.preset_version
    }
    #[must_use]
    pub const fn expires_at_unix_ms(&self) -> Option<i64> {
        self.expires_at_unix_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 1];
    const NON_V7_ID: [u8; 16] = [0, 0, 0, 0, 0, 0, 0x40, 0, 0x80, 0, 0, 0, 0, 0, 0, 2];

    fn request(workspace_id: [u8; 16], command_id: [u8; 16]) -> FullAccessChallengeRequestV1 {
        serde_json::from_value(serde_json::json!({
            "workspaceId": workspace_id,
            "commandId": command_id,
            "idempotencyKey": "challenge-test",
            "expectedAuthorizationRevision": 5,
            "presetVersion": 1,
            "expiresAtUnixMs": 1_000,
        }))
        .expect("challenge request wire DTO")
    }

    #[test]
    fn rejects_nil_and_non_v7_workspace_or_command_ids_from_wire_dto() {
        for (workspace_id, command_id) in [
            ([0; 16], VALID_ID),
            (NON_V7_ID, VALID_ID),
            (VALID_ID, [0; 16]),
            (VALID_ID, NON_V7_ID),
        ] {
            assert_eq!(
                request(workspace_id, command_id).validate(),
                Err(PermissionModeHostErrorV1::InvariantViolation),
            );
        }
    }

    #[test]
    fn preserves_valid_challenge_request_fields_from_wire_dto() {
        let validated = request(VALID_ID, VALID_ID)
            .validate()
            .expect("valid UUIDv7 challenge request");

        assert_eq!(validated.workspace_id().as_bytes(), &VALID_ID);
        assert_eq!(validated.command_id().as_bytes(), &VALID_ID);
        assert_eq!(validated.idempotency_key().as_str(), "challenge-test");
        assert_eq!(validated.expected_authorization_revision(), 5);
        assert_eq!(validated.preset_version(), PermissionPresetVersionV1::V1);
        assert_eq!(validated.expires_at_unix_ms(), Some(1_000));
    }
}
