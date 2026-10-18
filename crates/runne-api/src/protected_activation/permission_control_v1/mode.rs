/// Closed permission-mode choices carried by an issued challenge or consent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PermissionModeSelectionV1 {
    AskAlways,
    RiskBased,
    FullAccess,
}

/// Request address only: it refers to an already durable canonical command.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PermissionControlModeRequestV1;

/// Store-issued mode ceremony mirror. Labels are display data, never authority.
#[derive(Clone, PartialEq, Eq)]
pub struct PermissionControlModeChallengeV1 {
    pub principal: String,
    pub workspace_id: [u8; 16],
    pub workspace_label: String,
    pub expected_authorization_revision: u64,
    pub requested_mode: PermissionModeSelectionV1,
    pub preset_version: u16,
    pub mode_expires_at_unix_ms: Option<u64>,
    pub managed_policy_revision: u64,
    pub managed_policy_digest: [u8; 32],
    pub issued_challenge_binding_digest: [u8; 32],
    pub ceremony_expires_at_unix_ms: u64,
    pub native_warning_version: u16,
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 32],
}
