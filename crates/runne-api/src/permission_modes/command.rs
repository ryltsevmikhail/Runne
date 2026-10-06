use runne_domain::id::{
    CommandId, IdempotencyKey, InvalidIdReason, WorkspaceId, validate_uuid_v7_bytes,
};
use serde::{Deserialize, Serialize};

use super::{PermissionModeHostErrorV1, PermissionModeV1, PermissionPresetVersionV1};

/// Closed caller intent for a compare-and-set mode change.
///
/// Principal, managed policy, runtime authority, and native readiness are
/// deliberately absent; ingress and the current owners supply those values.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionModeChangeRequestV1 {
    workspace_id: WorkspaceId,
    command_id: CommandId,
    idempotency_key: String,
    expected_authorization_revision: u64,
    requested_mode: PermissionModeV1,
    preset_version: u16,
    expires_at_unix_ms: Option<i64>,
}

impl PermissionModeChangeRequestV1 {
    /// Builds a request from caller-selected semantics only.
    pub fn new(
        workspace_id: WorkspaceId,
        command_id: CommandId,
        idempotency_key: impl Into<String>,
        expected_authorization_revision: u64,
        requested_mode: PermissionModeV1,
        preset_version: u16,
        expires_at_unix_ms: Option<i64>,
    ) -> Self {
        Self {
            workspace_id,
            command_id,
            idempotency_key: idempotency_key.into(),
            expected_authorization_revision,
            requested_mode,
            preset_version,
            expires_at_unix_ms,
        }
    }

    /// Validates bounded canonical identifiers and freezes preset version 1.
    pub fn validate(self) -> Result<ValidatedPermissionModeChangeV1, PermissionModeHostErrorV1> {
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
        Ok(ValidatedPermissionModeChangeV1 {
            workspace_id: self.workspace_id,
            command_id: self.command_id,
            idempotency_key,
            expected_authorization_revision: self.expected_authorization_revision,
            requested_mode: self.requested_mode,
            preset_version,
            expires_at_unix_ms: self.expires_at_unix_ms,
        })
    }
}

/// Validated immutable command input used after API ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedPermissionModeChangeV1 {
    workspace_id: WorkspaceId,
    command_id: CommandId,
    idempotency_key: IdempotencyKey,
    expected_authorization_revision: u64,
    requested_mode: PermissionModeV1,
    preset_version: PermissionPresetVersionV1,
    expires_at_unix_ms: Option<i64>,
}

impl ValidatedPermissionModeChangeV1 {
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
    pub const fn requested_mode(&self) -> PermissionModeV1 {
        self.requested_mode
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

/// Stable validation disposition for malformed wire command fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionModeRequestErrorV1 {
    InvalidIdentifier,
    UnsupportedPresetVersion,
    InvalidExpiry,
    RevisionOutOfRange,
}

impl From<InvalidIdReason> for PermissionModeRequestErrorV1 {
    fn from(_: InvalidIdReason) -> Self {
        Self::InvalidIdentifier
    }
}
