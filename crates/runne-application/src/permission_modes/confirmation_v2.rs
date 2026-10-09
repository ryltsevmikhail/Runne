use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest, validate_uuid_v7_bytes};
use sha2::{Digest, Sha256};

use super::{PermissionMode, PermissionScope, PresetVersion};

const REQUEST_DOMAIN: &[u8] = b"runne:d21:permission-mode:public-request:v2\0";
const BINDING_DOMAIN: &[u8] = b"runne:d21:permission-mode:native-confirmation-binding:v2\0";

/// Exact semantic request and Store-issued ceremony binding for native consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeModeConfirmationBindingV2 {
    /// Canonical command identity reserved for this mode change.
    pub command_id: CommandId,
    /// Idempotency identity reserved for this mode change.
    pub idempotency_key: IdempotencyKey,
    /// Runtime authority, authenticated principal, and workspace boundary.
    pub scope: PermissionScope,
    /// Selection revision shown by the native confirmation.
    pub expected_authorization_revision: u64,
    /// Mode being confirmed; V2 confirmation applies to every mode.
    pub requested_mode: PermissionMode,
    /// Frozen preset being confirmed.
    pub preset_version: PresetVersion,
    /// Stable digest of the public request, independent of current policy/launch.
    pub public_request_digest: IntegrityDigest,
    /// T1 managed-policy revision captured for this issued ceremony.
    pub managed_policy_version: u64,
    /// T1 managed-policy digest captured for this issued ceremony.
    pub managed_policy_digest: IntegrityDigest,
    /// Store-issued purpose digest binding the nonce and captured owner context.
    pub challenge_binding_digest: IntegrityDigest,
    /// Exact protected session that owned the native signer at issuance.
    pub protected_session_id: [u8; 16],
    /// Optional selected-mode lifetime.
    pub expires_at_unix_ms: Option<i64>,
    /// Finite Store-issued ceremony expiry.
    pub challenge_expires_at_unix_ms: i64,
    /// Version of the native warning shown for this confirmation.
    pub native_warning_version: u16,
}

impl NativeModeConfirmationBindingV2 {
    /// Recomputes the stable request identity from its explicit fields.
    pub fn computed_public_request_digest(&self) -> IntegrityDigest {
        native_mode_public_request_digest_v2(
            self.command_id,
            &self.idempotency_key,
            &self.scope,
            self.expected_authorization_revision,
            self.requested_mode,
            self.preset_version,
            self.expires_at_unix_ms,
        )
    }

    /// Digest the verifier binds to the native proof transcript.
    pub fn digest(&self) -> IntegrityDigest {
        let mut hash = Sha256::new();
        hash.update(BINDING_DOMAIN);
        hash.update(self.public_request_digest.as_bytes());
        hash.update(self.managed_policy_version.to_be_bytes());
        hash.update(self.managed_policy_digest.as_bytes());
        hash.update(self.challenge_binding_digest.as_bytes());
        hash.update(self.protected_session_id);
        hash.update(self.challenge_expires_at_unix_ms.to_be_bytes());
        hash.update(self.native_warning_version.to_be_bytes());
        IntegrityDigest::from_bytes(hash.finalize().into())
    }
}

/// Trusted native owner that verifies proof of consent for one issued V2 ceremony.
pub trait NativeModeConfirmationVerifierV2: Send + Sync {
    /// Verify opaque native proof bytes and return the immutable issued challenge ID.
    fn verify(
        &self,
        binding: &NativeModeConfirmationBindingV2,
        proof_bytes: &[u8],
    ) -> Result<IntegrityDigest, NativeModeConfirmationError>;
}

/// Why a V2 native mode confirmation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeModeConfirmationError {
    /// The ceremony expired, is malformed, or is bound to another request.
    #[error("native mode confirmation was rejected")]
    Rejected,
    /// The trusted native confirmation authority is unavailable.
    #[error("native mode confirmation authority is unavailable")]
    AuthorityUnavailable,
    /// The verifier returned an invalid or mismatched challenge identifier.
    #[error("native mode confirmation proof receipt is invalid")]
    InvalidProofReceipt,
}

/// Opaque verified consent awaiting atomic Store consumption.
///
/// Construction is private and this type deliberately has no serialization
/// implementation. It is not a substitute for the legacy FullAccess proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedNativeModeConfirmationV2 {
    binding_digest: IntegrityDigest,
    proof_identifier: IntegrityDigest,
}

impl VerifiedNativeModeConfirmationV2 {
    fn verified(binding_digest: IntegrityDigest, proof_identifier: IntegrityDigest) -> Self {
        Self {
            binding_digest,
            proof_identifier,
        }
    }

    /// Digest of the exact public and issued ceremony binding verified natively.
    pub const fn binding_digest(self) -> IntegrityDigest {
        self.binding_digest
    }

    /// Store-issued challenge identifier consumed with the mode selection.
    pub const fn proof_identifier(self) -> IntegrityDigest {
        self.proof_identifier
    }
}

/// Computes the V2 stable public-request digest.
///
/// It intentionally excludes managed-policy and native-launch state so retries
/// can resolve the original ceremony or committed receipt before fresh checks.
#[allow(clippy::too_many_arguments)]
pub fn native_mode_public_request_digest_v2(
    command_id: CommandId,
    idempotency_key: &IdempotencyKey,
    scope: &PermissionScope,
    expected_authorization_revision: u64,
    requested_mode: PermissionMode,
    preset_version: PresetVersion,
    expires_at_unix_ms: Option<i64>,
) -> IntegrityDigest {
    let mut hash = Sha256::new();
    hash.update(REQUEST_DOMAIN);
    put_bytes(&mut hash, scope.runtime_authority_id.0.as_bytes());
    put_bytes(&mut hash, scope.principal_id.as_str().as_bytes());
    put_bytes(&mut hash, idempotency_key.as_str().as_bytes());
    hash.update(scope.workspace_id.as_bytes());
    hash.update(command_id.as_bytes());
    hash.update(expected_authorization_revision.to_be_bytes());
    hash.update([mode_tag(requested_mode)]);
    hash.update(preset_version.as_u16().to_be_bytes());
    match expires_at_unix_ms {
        Some(expiry) => {
            hash.update([1]);
            hash.update(expiry.to_be_bytes());
        }
        None => hash.update([0]),
    }
    IntegrityDigest::from_bytes(hash.finalize().into())
}

/// Verify fresh native consent for any selected mode and return an opaque proof.
pub fn verify_native_mode_confirmation_v2(
    binding: &NativeModeConfirmationBindingV2,
    proof_bytes: &[u8],
    now_unix_ms: i64,
    verifier: &dyn NativeModeConfirmationVerifierV2,
) -> Result<VerifiedNativeModeConfirmationV2, NativeModeConfirmationError> {
    if binding.challenge_expires_at_unix_ms <= 0
        || binding.challenge_expires_at_unix_ms <= now_unix_ms
        || binding.native_warning_version == 0
        || binding
            .public_request_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || binding
            .challenge_binding_digest
            .as_bytes()
            .iter()
            .all(|byte| *byte == 0)
        || validate_uuid_v7_bytes(&binding.protected_session_id).is_err()
        || binding.computed_public_request_digest() != binding.public_request_digest
    {
        return Err(NativeModeConfirmationError::Rejected);
    }
    let proof_identifier = verifier.verify(binding, proof_bytes)?;
    if proof_identifier != binding.challenge_binding_digest
        || proof_identifier.as_bytes().iter().all(|byte| *byte == 0)
    {
        return Err(NativeModeConfirmationError::InvalidProofReceipt);
    }
    Ok(VerifiedNativeModeConfirmationV2::verified(
        binding.digest(),
        proof_identifier,
    ))
}

fn mode_tag(mode: PermissionMode) -> u8 {
    match mode {
        PermissionMode::AskAlways => 1,
        PermissionMode::RiskBased => 2,
        PermissionMode::FullAccess => 3,
    }
}

fn put_bytes(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

#[cfg(test)]
#[path = "confirmation_v2_tests.rs"]
mod tests;
