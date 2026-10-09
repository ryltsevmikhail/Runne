use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::project_trust::ManagedEffectDecision;

use super::{
    AdminError, CurrentPolicyAdmin, ReservedManagedPolicyCommandV1,
    managed_policy_command_digest_v1, policy_admin_session_binding_digest,
};

/// Exact native warning, nonce, six rules, CAS and current launch transcript.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ManagedPolicyConsentBindingV1 {
    command_id: [u8; 16],
    command_digest: [u8; 32],
    project_id: [u8; 16],
    instance_epoch: u64,
    expected_revision: u64,
    old_rules_digest: [u8; 32],
    new_rules_digest: [u8; 32],
    rules: [ManagedEffectDecision; 6],
    admin_generation: u64,
    launch_binding_digest: [u8; 32],
    challenge_id: [u8; 16],
    challenge_nonce: [u8; 32],
    warning_version: u16,
    issued_at_unix_ms: i64,
    expires_at_unix_ms: i64,
    binding_digest: [u8; 32],
}

impl ManagedPolicyConsentBindingV1 {
    fn from_command(command: &ReservedManagedPolicyCommandV1) -> Self {
        let mut binding = Self {
            command_id: *command.command_id(),
            command_digest: *command.semantic_digest(),
            project_id: *command.project().as_bytes(),
            instance_epoch: command.expected().instance_epoch,
            expected_revision: command.expected().revision,
            old_rules_digest: *command.old_rules_digest(),
            new_rules_digest: *command.new_rules_digest(),
            rules: command.rules().decisions(),
            admin_generation: command.admin_generation(),
            launch_binding_digest: *command.launch_binding_digest(),
            challenge_id: *command.challenge_id(),
            challenge_nonce: *command.challenge_nonce(),
            warning_version: command.warning_version(),
            issued_at_unix_ms: command.issued_at_unix_ms(),
            expires_at_unix_ms: command.expires_at_unix_ms(),
            binding_digest: [0; 32],
        };
        binding.binding_digest = consent_binding_digest(&binding);
        binding
    }

    pub const fn command_id(&self) -> &[u8; 16] {
        &self.command_id
    }
    pub const fn command_digest(&self) -> &[u8; 32] {
        &self.command_digest
    }
    pub const fn project_id(&self) -> &[u8; 16] {
        &self.project_id
    }
    pub const fn instance_epoch(&self) -> u64 {
        self.instance_epoch
    }
    pub const fn expected_revision(&self) -> u64 {
        self.expected_revision
    }
    pub const fn old_rules_digest(&self) -> &[u8; 32] {
        &self.old_rules_digest
    }
    pub const fn new_rules_digest(&self) -> &[u8; 32] {
        &self.new_rules_digest
    }
    pub const fn rules(&self) -> [ManagedEffectDecision; 6] {
        self.rules
    }
    pub const fn admin_generation(&self) -> u64 {
        self.admin_generation
    }
    pub const fn launch_binding_digest(&self) -> &[u8; 32] {
        &self.launch_binding_digest
    }
    pub const fn challenge_id(&self) -> &[u8; 16] {
        &self.challenge_id
    }
    pub const fn challenge_nonce(&self) -> &[u8; 32] {
        &self.challenge_nonce
    }
    pub const fn warning_version(&self) -> u16 {
        self.warning_version
    }
    pub const fn issued_at_unix_ms(&self) -> i64 {
        self.issued_at_unix_ms
    }
    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }
    pub const fn binding_digest(&self) -> &[u8; 32] {
        &self.binding_digest
    }
}

/// Trusted native owner for the exact managed-policy warning and nonce.
///
/// Production composition must pin the daemon-owned verifier. Tests may use a
/// mock port; this trait alone does not qualify a production native signer.
pub trait ManagedPolicyConsentVerifierV1: Send + Sync {
    /// Verify protected native proof bytes and return the issued challenge ID.
    fn verify(
        &self,
        binding: &ManagedPolicyConsentBindingV1,
        proof_bytes: &[u8],
    ) -> Result<[u8; 16], AdminError>;
}

/// Opaque App proof accepted by Store only for its exact pending command.
pub struct VerifiedManagedPolicyConsentV1 {
    command_id: [u8; 16],
    command_digest: [u8; 32],
    challenge_id: [u8; 16],
    challenge_nonce: [u8; 32],
    admin_generation: u64,
    launch_binding_digest: [u8; 32],
    consent_binding_digest: [u8; 32],
    verified_at_unix_ms: i64,
}

impl VerifiedManagedPolicyConsentV1 {
    pub const fn command_id(&self) -> &[u8; 16] {
        &self.command_id
    }
    pub const fn command_digest(&self) -> &[u8; 32] {
        &self.command_digest
    }
    pub const fn challenge_id(&self) -> &[u8; 16] {
        &self.challenge_id
    }
    pub const fn challenge_nonce(&self) -> &[u8; 32] {
        &self.challenge_nonce
    }
    pub const fn admin_generation(&self) -> u64 {
        self.admin_generation
    }
    pub const fn launch_binding_digest(&self) -> &[u8; 32] {
        &self.launch_binding_digest
    }
    pub const fn consent_binding_digest(&self) -> &[u8; 32] {
        &self.consent_binding_digest
    }
    pub const fn verified_at_unix_ms(&self) -> i64 {
        self.verified_at_unix_ms
    }
}

/// Verifies one fresh native consent and creates the private App proof.
pub fn verify_managed_policy_consent_v1(
    current: &CurrentPolicyAdmin<'_>,
    command: &ReservedManagedPolicyCommandV1,
    proof_bytes: &[u8],
    verifier: &dyn ManagedPolicyConsentVerifierV1,
) -> Result<VerifiedManagedPolicyConsentV1, AdminError> {
    let now_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| i64::try_from(duration.as_millis()).ok())
        .filter(|value| *value > 0)
        .ok_or(AdminError::Unavailable)?;
    if command.semantic_digest() != &managed_policy_command_digest_v1(command)
        || command.launch_binding_digest()
            != &policy_admin_session_binding_digest(current.binding())
        || command.issued_at_unix_ms() > now_unix_ms
        || command.expires_at_unix_ms() <= now_unix_ms
    {
        return Err(AdminError::Rejected);
    }
    let binding = ManagedPolicyConsentBindingV1::from_command(command);
    let verified_challenge = verifier.verify(&binding, proof_bytes)?;
    if verified_challenge != binding.challenge_id {
        return Err(AdminError::Rejected);
    }
    Ok(VerifiedManagedPolicyConsentV1 {
        command_id: binding.command_id,
        command_digest: binding.command_digest,
        challenge_id: binding.challenge_id,
        challenge_nonce: binding.challenge_nonce,
        admin_generation: binding.admin_generation,
        launch_binding_digest: binding.launch_binding_digest,
        consent_binding_digest: binding.binding_digest,
        verified_at_unix_ms: now_unix_ms,
    })
}

fn consent_binding_digest(binding: &ManagedPolicyConsentBindingV1) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"runne.managed-policy-consent-binding.v1\0");
    hash.update(binding.command_id);
    hash.update(binding.command_digest);
    hash.update(binding.project_id);
    hash.update(binding.instance_epoch.to_be_bytes());
    hash.update(binding.expected_revision.to_be_bytes());
    hash.update(binding.old_rules_digest);
    hash.update(binding.new_rules_digest);
    for rule in binding.rules {
        hash.update([rule.tag()]);
    }
    hash.update(binding.admin_generation.to_be_bytes());
    hash.update(binding.launch_binding_digest);
    hash.update(binding.challenge_id);
    hash.update(binding.challenge_nonce);
    hash.update(binding.warning_version.to_be_bytes());
    hash.update(binding.issued_at_unix_ms.to_be_bytes());
    hash.update(binding.expires_at_unix_ms.to_be_bytes());
    hash.finalize().into()
}
