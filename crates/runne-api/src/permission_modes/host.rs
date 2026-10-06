//! Runtime-owned permission-mode port used by HTTP, CLI, and Desktop clients.

use super::{
    FullAccessChallengeRequestV1, PermissionModeChangeReceiptV1, PermissionModeChangeRequestV1,
    PermissionModeHostErrorV1, PermissionModeStatusV1, ValidatedFullAccessChallengeRequestV1,
    ValidatedPermissionModeChangeV1,
};

/// Public status, challenge, and compare-and-set operations.
pub trait PermissionModeHostV1 {
    /// Loads the current selected mode and honest effective enforcement state.
    fn status(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
    ) -> Result<PermissionModeStatusV1, PermissionModeHostErrorV1>;

    /// Issues a purpose-bound full-access challenge. The nonce stays native-only.
    fn issue_full_access_challenge(
        &self,
        request: ValidatedFullAccessChallengeRequestV1,
    ) -> Result<PermissionModeChallengeIssuedV1, PermissionModeHostErrorV1>;

    /// Commits an exact mode change after ingress has verified native proof.
    fn set_mode(
        &self,
        request: ValidatedPermissionModeChangeV1,
        native_proof: Option<&[u8]>,
    ) -> Result<PermissionModeChangeReceiptV1, PermissionModeHostErrorV1>;
}

/// Public challenge acknowledgement. It intentionally omits nonce and proof bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionModeChallengeIssuedV1 {
    pub command_id: runne_domain::id::CommandId,
    pub expires_at_unix_ms: i64,
}

/// Maps an unvalidated wire request into the host's validated challenge input.
pub fn validate_challenge_request(
    request: FullAccessChallengeRequestV1,
) -> Result<ValidatedFullAccessChallengeRequestV1, PermissionModeHostErrorV1> {
    request.validate()
}

/// Maps an unvalidated wire request into the host's validated mode-change input.
pub fn validate_mode_change_request(
    request: PermissionModeChangeRequestV1,
) -> Result<ValidatedPermissionModeChangeV1, PermissionModeHostErrorV1> {
    request.validate()
}
