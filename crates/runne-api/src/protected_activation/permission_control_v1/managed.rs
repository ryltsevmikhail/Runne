/// Closed T1 managed-policy decisions in fixed canonical action order.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ManagedDecisionV1 {
    Allow,
    Ask,
    Deny,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManagedPolicyV1 {
    pub fs_read: ManagedDecisionV1,
    pub fs_create: ManagedDecisionV1,
    pub fs_write: ManagedDecisionV1,
    pub fs_delete: ManagedDecisionV1,
    pub process_start: ManagedDecisionV1,
    pub network_use: ManagedDecisionV1,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PermissionControlManagedRequestV1;

/// Store-issued administrator proposal. Role is represented by stable registration evidence,
/// never by a role string or an identity granted by this wire message.
#[derive(Clone, PartialEq, Eq)]
pub struct PermissionControlManagedChallengeV1 {
    pub registered_administrator_digest: [u8; 32],
    pub registration_generation: u64,
    pub project_id: [u8; 16],
    pub project_label: String,
    pub expected_t1_epoch: u64,
    pub expected_t1_revision: u64,
    pub current_policy: ManagedPolicyV1,
    pub requested_policy: ManagedPolicyV1,
    pub current_policy_digest: [u8; 32],
    pub requested_policy_digest: [u8; 32],
    pub managed_schema_version: u16,
    pub source_schema_version: u16,
    pub local_command_schema_version: u16,
    pub issued_challenge_binding_digest: [u8; 32],
    pub ceremony_expires_at_unix_ms: u64,
    pub native_warning_version: u16,
    pub challenge_id: [u8; 16],
    pub nonce: [u8; 32],
}
