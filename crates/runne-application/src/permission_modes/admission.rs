//! Runtime-host ports for validating re-auth proof and admitting native scope.

use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest};
use sha2::{Digest, Sha256};

use super::{
    composite::CompositeEffectScope,
    model::{PermissionMode, PermissionScope, PresetVersion},
};

/// Trusted runtime-host boundary that admits one composite scope in its native executor.
pub trait NativeScopeAdmissionPort: Send + Sync {
    /// Check effective-mode implementation readiness for a capability scope.
    ///
    /// This evidence is never a grant and its handle must not be accepted by
    /// the launch path. `FullAccess` adapters can report broad backend
    /// capability while exact managed invocation scopes are admitted below.
    fn admit_mode_readiness(
        &self,
        mode: PermissionMode,
        scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError>;

    /// Return a scope-bound receipt after existing-executor admission succeeds.
    ///
    /// A platform adapter may use this receipt as a handle to native held-root
    /// descriptors. The application projection stores only the opaque digest.
    fn admit_scope(
        &self,
        scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError>;
}

/// Trusted runtime-host boundary that consumes a fresh full-access challenge.
pub trait NativeChallengeVerifier: Send + Sync {
    /// Verify opaque proof bytes and return the immutable issued challenge ID.
    ///
    /// This validates cryptographic proof only. The mode-change Store owner
    /// must consume the nonce and persist its receipt atomically with the
    /// authorization revision and idempotency result.
    fn verify(
        &self,
        binding: &FullAccessChallengeBinding,
        proof_bytes: &[u8],
    ) -> Result<IntegrityDigest, NativeChallengeError>;
}

/// Semantic command fields bound into fresh full-access re-authentication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullAccessChallengeBinding {
    /// Command identifier bound by the Store-issued challenge record.
    pub command_id: CommandId,
    /// Idempotency identity bound by the Store-issued challenge record.
    pub idempotency_key: IdempotencyKey,
    /// Runtime authority, authenticated principal, workspace.
    pub scope: PermissionScope,
    /// Mode revision the human saw before confirmation.
    pub expected_authorization_revision: u64,
    /// Only a full-access selection uses this challenge.
    pub requested_mode: PermissionMode,
    /// Frozen mode preset.
    pub preset_version: PresetVersion,
    /// Managed-policy version observed by the runtime.
    pub managed_policy_version: u64,
    /// Exact managed-policy snapshot digest observed by the runtime.
    pub managed_policy_digest: IntegrityDigest,
    /// Caller-computed semantic intent digest checked by runtime.
    pub intent_digest: IntegrityDigest,
    /// Challenge nonce and purpose digest issued by trusted host.
    pub challenge_binding_digest: IntegrityDigest,
    /// Command expiry bound into the user's intent, if any.
    pub expires_at_unix_ms: Option<i64>,
    /// Short, mandatory expiry of this challenge, separate from mode lifetime.
    pub challenge_expires_at_unix_ms: i64,
}

impl FullAccessChallengeBinding {
    /// Canonical digest used to prevent proof substitution across commands.
    pub fn digest(&self) -> IntegrityDigest {
        let mut hash = Sha256::new();
        hash.update(b"runne:d21:full-access-challenge-binding:v1\0");
        hash.update(self.command_id.as_bytes());
        put_bytes(&mut hash, self.idempotency_key.as_str().as_bytes());
        put_bytes(&mut hash, self.scope.runtime_authority_id.0.as_bytes());
        put_bytes(&mut hash, self.scope.principal_id.as_str().as_bytes());
        hash.update(self.scope.workspace_id.as_bytes());
        hash.update(self.expected_authorization_revision.to_be_bytes());
        hash.update([match self.requested_mode {
            PermissionMode::AskAlways => 1,
            PermissionMode::RiskBased => 2,
            PermissionMode::FullAccess => 3,
        }]);
        hash.update(self.preset_version.as_u16().to_be_bytes());
        hash.update(self.managed_policy_version.to_be_bytes());
        hash.update(self.managed_policy_digest.as_bytes());
        hash.update(self.intent_digest.as_bytes());
        hash.update(self.challenge_binding_digest.as_bytes());
        match self.expires_at_unix_ms {
            Some(value) => {
                hash.update([1]);
                hash.update(value.to_be_bytes());
            }
            None => hash.update([0]),
        }
        hash.update(self.challenge_expires_at_unix_ms.to_be_bytes());
        IntegrityDigest::from_bytes(hash.finalize().into())
    }
}

/// Why native full-access scope admission could not be completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeAdmissionError {
    /// No native enforcement receipt is available for the requested scope.
    EnforcementUnavailable,
    /// The managed composite scope has no enforceable representation.
    CompositePolicyUnenforceable,
}

/// Why fresh native full-access proof was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeChallengeError {
    /// Challenge is expired, invalid, or bound to another command.
    Rejected,
    /// Trusted local re-authentication authority is unavailable.
    AuthorityUnavailable,
    /// Caller attempted to use full-access proof flow for another mode.
    WrongMode,
    /// Verifier returned an invalid empty proof identifier.
    InvalidProofReceipt,
}

fn put_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u32).to_be_bytes());
    hash.update(value);
}
