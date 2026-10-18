use crate::project_trust::{
    ManagedEffectPolicyV1, ProjectTrustEffectPolicySnapshot, ProjectTrustProjectId, TrustToken,
};

pub use super::digest_encoding::{
    managed_policy_command_digest_v1, managed_policy_request_digest_v1,
    policy_admin_session_binding_digest, policy_admin_stable_identity_digest,
};
use super::model::{AdminError, PolicyAdminSessionBinding};

const MAX_CEREMONY_TTL_MS: i64 = 120_000;

/// Exact semantic request before Store issues a fresh challenge and clock deadline.
#[derive(Clone, PartialEq, Eq)]
pub struct ManagedPolicyCommandV1 {
    command_id: [u8; 16],
    idempotency_key: String,
    project: ProjectTrustProjectId,
    expected: TrustToken,
    old_rules_digest: [u8; 32],
    new_rules_digest: [u8; 32],
    rules: ManagedEffectPolicyV1,
    admin_generation: u64,
    launch_binding_digest: [u8; 32],
    warning_version: u16,
    request_digest: [u8; 32],
}

impl ManagedPolicyCommandV1 {
    /// Captures exact T1 CAS state and all six rules; Store mints ceremony fields later.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command_id: [u8; 16],
        idempotency_key: impl Into<String>,
        project: ProjectTrustProjectId,
        snapshot: ProjectTrustEffectPolicySnapshot,
        rules: ManagedEffectPolicyV1,
        admin_generation: u64,
        binding: &PolicyAdminSessionBinding,
        warning_version: u16,
    ) -> Result<Self, AdminError> {
        let idempotency_key = idempotency_key.into();
        if command_id == [0; 16]
            || idempotency_key.is_empty()
            || idempotency_key.len() > 256
            || idempotency_key
                .bytes()
                .any(|b| b == 0 || b < 0x20 || b == 0x7f)
            || !snapshot.is_valid()
            || snapshot.record.revision == 0
            || !rules.is_valid()
            || admin_generation == 0
            || warning_version == 0
            || binding.protected_launch_id() == &[0; 16]
            || binding.desktop_generation_key() == &[0; 32]
            || binding.session_key_epoch() == 0
        {
            return Err(AdminError::Rejected);
        }
        let expected = snapshot.record.token();
        let old_rules_digest =
            crate::project_trust::managed_effect_policy_digest_v2(project, &snapshot)
                .ok_or(AdminError::Rejected)?;
        let next_revision = snapshot
            .record
            .revision
            .checked_add(1)
            .ok_or(AdminError::Rejected)?;
        let next_snapshot = ProjectTrustEffectPolicySnapshot {
            record: crate::project_trust::ProjectTrustRecord {
                revision: next_revision,
                ..snapshot.record
            },
            policy: rules,
        };
        let new_rules_digest =
            crate::project_trust::managed_effect_policy_digest_v2(project, &next_snapshot)
                .ok_or(AdminError::Rejected)?;
        let mut command = Self {
            command_id,
            idempotency_key,
            project,
            expected,
            old_rules_digest,
            new_rules_digest,
            rules,
            admin_generation,
            launch_binding_digest: policy_admin_session_binding_digest(binding),
            warning_version,
            request_digest: [0; 32],
        };
        command.request_digest = managed_policy_request_digest_v1(&command);
        Ok(command)
    }

    /// Reconstitutes the exact result of Store-issued nonce and finite clock fields.
    ///
    /// This creates a command value only; Store still checks its persisted row,
    /// fresh issue time, nonce uniqueness, role generation and session deadline.
    #[allow(clippy::too_many_arguments)]
    pub fn issued_by_store(
        &self,
        challenge_id: [u8; 16],
        challenge_nonce: [u8; 32],
        issued_at_unix_ms: i64,
        expires_at_unix_ms: i64,
        authenticated_session_deadline_ms: i64,
    ) -> Result<ReservedManagedPolicyCommandV1, AdminError> {
        let ttl = expires_at_unix_ms.saturating_sub(issued_at_unix_ms);
        if challenge_id == [0; 16]
            || challenge_nonce == [0; 32]
            || issued_at_unix_ms <= 0
            || ttl <= 0
            || ttl > MAX_CEREMONY_TTL_MS
            || issued_at_unix_ms >= authenticated_session_deadline_ms
            || expires_at_unix_ms > authenticated_session_deadline_ms
        {
            return Err(AdminError::Rejected);
        }
        let mut reserved = ReservedManagedPolicyCommandV1 {
            request_digest: self.request_digest,
            request: self.clone(),
            challenge_id,
            challenge_nonce,
            issued_at_unix_ms,
            expires_at_unix_ms,
            semantic_digest: [0; 32],
        };
        reserved.semantic_digest = managed_policy_command_digest_v1(&reserved);
        Ok(reserved)
    }

    pub const fn command_id(&self) -> &[u8; 16] {
        &self.command_id
    }
    pub fn idempotency_key(&self) -> &str {
        &self.idempotency_key
    }
    pub const fn project(&self) -> ProjectTrustProjectId {
        self.project
    }
    pub const fn expected(&self) -> TrustToken {
        self.expected
    }
    pub const fn old_rules_digest(&self) -> &[u8; 32] {
        &self.old_rules_digest
    }
    pub const fn new_rules_digest(&self) -> &[u8; 32] {
        &self.new_rules_digest
    }
    pub const fn rules(&self) -> ManagedEffectPolicyV1 {
        self.rules
    }
    pub const fn admin_generation(&self) -> u64 {
        self.admin_generation
    }
    pub const fn launch_binding_digest(&self) -> &[u8; 32] {
        &self.launch_binding_digest
    }
    pub const fn warning_version(&self) -> u16 {
        self.warning_version
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
}

/// Store-issued exact command, including challenge, nonce, warning and finite expiry.
#[derive(PartialEq, Eq)]
pub struct ReservedManagedPolicyCommandV1 {
    request: ManagedPolicyCommandV1,
    request_digest: [u8; 32],
    challenge_id: [u8; 16],
    challenge_nonce: [u8; 32],
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    semantic_digest: [u8; 32],
}

impl ReservedManagedPolicyCommandV1 {
    pub const fn request(&self) -> &ManagedPolicyCommandV1 {
        &self.request
    }
    pub const fn command_id(&self) -> &[u8; 16] {
        self.request.command_id()
    }
    pub fn idempotency_key(&self) -> &str {
        self.request.idempotency_key()
    }
    pub const fn project(&self) -> ProjectTrustProjectId {
        self.request.project()
    }
    pub const fn expected(&self) -> TrustToken {
        self.request.expected()
    }
    pub const fn old_rules_digest(&self) -> &[u8; 32] {
        self.request.old_rules_digest()
    }
    pub const fn new_rules_digest(&self) -> &[u8; 32] {
        self.request.new_rules_digest()
    }
    pub const fn rules(&self) -> ManagedEffectPolicyV1 {
        self.request.rules()
    }
    pub const fn admin_generation(&self) -> u64 {
        self.request.admin_generation()
    }
    pub const fn launch_binding_digest(&self) -> &[u8; 32] {
        self.request.launch_binding_digest()
    }
    pub const fn warning_version(&self) -> u16 {
        self.request.warning_version()
    }
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }
    pub const fn challenge_id(&self) -> &[u8; 16] {
        &self.challenge_id
    }
    pub const fn challenge_nonce(&self) -> &[u8; 32] {
        &self.challenge_nonce
    }
    pub const fn issued_at_unix_ms(&self) -> i64 {
        self.issued_at_unix_ms
    }
    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }
    pub const fn semantic_digest(&self) -> &[u8; 32] {
        &self.semantic_digest
    }
}
