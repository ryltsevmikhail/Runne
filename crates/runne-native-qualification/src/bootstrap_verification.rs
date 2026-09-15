use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;

use crate::{
    PendingQualificationRunBootstrapProof, QualificationRunBootstrapError,
    QualificationRunBootstrapExpectation, VerifiedQualificationRunBootstrapProof,
};

const MAX_ADMISSION_SECONDS: u64 = 15 * 60;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Stateful verifier for a separate signed run-level bootstrap domain.
pub struct QualificationRunBootstrapVerifier {
    policy: Option<crate::context_policy::ContextVerificationPolicy>,
    consumed_context_ids: HashSet<[u8; 32]>,
    consumed_nonces: HashSet<[u8; 32]>,
}

impl QualificationRunBootstrapVerifier {
    /// Loads the compile-time context authority for the separate bootstrap domain.
    #[must_use]
    pub fn from_compiled_policy() -> Self {
        Self::with_policy(crate::bootstrap_policy::load())
    }

    /// Verifies one move-only proof against exact independent expectations.
    ///
    /// # Errors
    ///
    /// Rejects unavailable authority, any canonical wire, time, signature,
    /// binding, or replay mismatch. Replay identities are process-local only.
    pub fn verify_and_consume(
        &mut self,
        proof: PendingQualificationRunBootstrapProof,
        expected: &QualificationRunBootstrapExpectation,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationRunBootstrapProof, QualificationRunBootstrapError> {
        proof.verify_and_consume(self, expected, now_unix_seconds)
    }

    pub(crate) fn verify_bytes_and_consume(
        &mut self,
        bytes: &[u8],
        expected: &QualificationRunBootstrapExpectation,
        now: u64,
    ) -> Result<VerifiedQualificationRunBootstrapProof, QualificationRunBootstrapError> {
        let policy = self
            .policy
            .as_ref()
            .ok_or(QualificationRunBootstrapError::PolicyUnavailable)?;
        let proof = crate::bootstrap_wire::decode(bytes)?;
        let shape = shape(&proof)?;
        if now > MAX_SAFE_JSON_INTEGER
            || !valid_admission_window(proof.issued_at, proof.expires_at)
            || proof.issued_at > now
            || proof.expires_at <= now
        {
            return Err(QualificationRunBootstrapError::InvalidTime);
        }
        if shape.key_id != policy.key_id {
            return Err(QualificationRunBootstrapError::InvalidSignature);
        }
        policy
            .key
            .verify_strict(
                &crate::bootstrap_wire::signing_payload(&proof)?,
                &Signature::from_bytes(&shape.signature),
            )
            .map_err(|_| QualificationRunBootstrapError::InvalidSignature)?;
        if shape.context_id != expected.context_id
            || shape.nonce != expected.nonce
            || shape.challenge != expected.challenge
            || proof.issued_at != expected.issued_at
            || proof.expires_at != expected.expires_at
            || proof.run_not_after != expected.run_not_after
            || !valid_run_deadline(
                proof.issued_at,
                proof.expires_at,
                proof.run_not_after,
                expected.max_run_duration_seconds,
            )
            || shape.candidate_sha256 != expected.candidate_sha256
            || shape.raw_v3_tuple_sha256 != expected.raw_v3_tuple_sha256
            || shape.source_revision != expected.source_revision
            || proof.workflow_run_id != expected.workflow_run_id
            || shape.namespace_sha256 != expected.namespace_sha256
            || shape.manifest_sha256 != expected.manifest_sha256
            || shape.profile_sha256 != expected.profile_sha256
        {
            return Err(QualificationRunBootstrapError::BindingMismatch);
        }
        if self.consumed_context_ids.contains(&shape.context_id)
            || self.consumed_nonces.contains(&shape.nonce)
        {
            return Err(QualificationRunBootstrapError::Replay);
        }
        self.consumed_context_ids.insert(shape.context_id);
        self.consumed_nonces.insert(shape.nonce);
        Ok(VerifiedQualificationRunBootstrapProof::verified(expected))
    }

    pub(crate) fn with_policy(
        policy: Option<crate::context_policy::ContextVerificationPolicy>,
    ) -> Self {
        Self {
            policy,
            consumed_context_ids: HashSet::new(),
            consumed_nonces: HashSet::new(),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    #[doc(hidden)]
    #[must_use]
    pub fn test_only_from_verifying_key(key: ed25519_dalek::VerifyingKey) -> Self {
        use sha2::{Digest as _, Sha256};
        Self::with_policy(Some(crate::context_policy::ContextVerificationPolicy {
            key_id: Sha256::digest(key.as_bytes()).into(),
            key,
        }))
    }
}

struct Shape {
    context_id: [u8; 32],
    nonce: [u8; 32],
    challenge: [u8; 32],
    candidate_sha256: [u8; 32],
    raw_v3_tuple_sha256: [u8; 32],
    source_revision: [u8; 20],
    namespace_sha256: [u8; 32],
    manifest_sha256: [u8; 32],
    profile_sha256: [u8; 32],
    key_id: [u8; 32],
    signature: [u8; 64],
}

fn shape(
    proof: &crate::bootstrap_wire::RunBootstrapWire,
) -> Result<Shape, QualificationRunBootstrapError> {
    if proof.schema_version != crate::bootstrap_wire::SCHEMA_VERSION
        || proof.signature.algorithm != "ed25519"
        || !crate::model::valid_run_id(&proof.workflow_run_id)
    {
        return Err(QualificationRunBootstrapError::InvalidProof);
    }
    let shape = Shape {
        context_id: hex_id(&proof.context_id)?,
        nonce: base64_id(&proof.nonce)?,
        challenge: hex_id(&proof.challenge)?,
        candidate_sha256: hex_id(&proof.candidate_sha256)?,
        raw_v3_tuple_sha256: hex_id(&proof.raw_v3_tuple_sha256)?,
        source_revision: hex_id(&proof.source_revision)?,
        namespace_sha256: hex_id(&proof.namespace_sha256)?,
        manifest_sha256: hex_id(&proof.manifest_sha256)?,
        profile_sha256: hex_id(&proof.profile_sha256)?,
        key_id: hex_id(&proof.signature.key_id)?,
        signature: base64_id(&proof.signature.value)?,
    };
    let zero = [
        shape.context_id,
        shape.nonce,
        shape.challenge,
        shape.candidate_sha256,
        shape.raw_v3_tuple_sha256,
        shape.namespace_sha256,
        shape.manifest_sha256,
        shape.profile_sha256,
    ];
    if zero.into_iter().any(|value| value == [0; 32]) || shape.source_revision == [0; 20] {
        return Err(QualificationRunBootstrapError::InvalidProof);
    }
    Ok(shape)
}

pub const fn valid_admission_window(issued_at: u64, expires_at: u64) -> bool {
    issued_at <= MAX_SAFE_JSON_INTEGER
        && expires_at <= MAX_SAFE_JSON_INTEGER
        && matches!(
            expires_at.checked_sub(issued_at),
            Some(1..=MAX_ADMISSION_SECONDS)
        )
}

pub fn valid_run_deadline(
    issued_at: u64,
    expires_at: u64,
    run_not_after: u64,
    max_run_duration_seconds: u64,
) -> bool {
    max_run_duration_seconds != 0
        && max_run_duration_seconds <= MAX_SAFE_JSON_INTEGER
        && run_not_after <= MAX_SAFE_JSON_INTEGER
        && expires_at <= run_not_after
        && run_not_after
            .checked_sub(issued_at)
            .is_some_and(|duration| duration != 0 && duration <= max_run_duration_seconds)
}

fn hex_id<const N: usize>(value: &str) -> Result<[u8; N], QualificationRunBootstrapError> {
    let bytes: [u8; N] = hex::decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(QualificationRunBootstrapError::InvalidProof)?;
    (hex::encode(bytes) == value)
        .then_some(bytes)
        .ok_or(QualificationRunBootstrapError::InvalidProof)
}

fn base64_id<const N: usize>(value: &str) -> Result<[u8; N], QualificationRunBootstrapError> {
    let bytes: [u8; N] = URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or(QualificationRunBootstrapError::InvalidProof)?;
    (URL_SAFE_NO_PAD.encode(bytes) == value)
        .then_some(bytes)
        .ok_or(QualificationRunBootstrapError::InvalidProof)
}
