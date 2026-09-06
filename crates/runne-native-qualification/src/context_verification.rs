use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;

use crate::context_model::{
    QualificationRunContextError, QualificationRunContextExpectation, QualificationScenario,
    VerifiedQualificationRunContext,
};
use crate::context_policy::{self, ContextVerificationPolicy};
use crate::context_wire::{self, RunContextWire};
use crate::{QualificationFaultSelector, QualificationProcessRole};

const MAX_CONTEXT_LIFETIME_SECONDS: u64 = 15 * 60;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Stateful verifier using only the separately compiled runner-context policy.
pub struct QualificationRunContextVerifier {
    policy: Option<ContextVerificationPolicy>,
    consumed_context_ids: HashSet<[u8; 32]>,
    consumed_nonces: HashSet<[u8; 32]>,
}

impl QualificationRunContextVerifier {
    /// Loads only the runner-context authority embedded at compile time.
    #[must_use]
    pub fn from_compiled_policy() -> Self {
        Self::with_policy(context_policy::load())
    }

    fn with_policy(policy: Option<ContextVerificationPolicy>) -> Self {
        Self {
            policy,
            consumed_context_ids: HashSet::new(),
            consumed_nonces: HashSet::new(),
        }
    }

    /// Verifies exact independent bindings and consumes local replay identities.
    ///
    /// # Errors
    ///
    /// Fails closed for unavailable policy or any shape, time, signature,
    /// binding, role, selector, or replay mismatch.
    pub fn verify_and_consume(
        &mut self,
        bytes: &[u8],
        expected: &QualificationRunContextExpectation,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationRunContext, QualificationRunContextError> {
        let policy = self
            .policy
            .as_ref()
            .ok_or(QualificationRunContextError::PolicyUnavailable)?;
        let context = context_wire::decode(bytes)?;
        let verified = verify_context(&context, expected, now_unix_seconds, policy)?;
        if self.consumed_context_ids.contains(&verified.context_id())
            || self.consumed_nonces.contains(&verified.nonce())
        {
            return Err(QualificationRunContextError::Replay);
        }
        self.consumed_context_ids.insert(verified.context_id());
        self.consumed_nonces.insert(verified.nonce());
        Ok(verified)
    }

    #[cfg(test)]
    pub(super) fn for_test(key: ed25519_dalek::VerifyingKey) -> Self {
        use sha2::{Digest as _, Sha256};
        let key_id = Sha256::digest(key.as_bytes()).into();
        Self::with_policy(Some(ContextVerificationPolicy { key, key_id }))
    }
}

pub struct AdmittedRunContextShape {
    pub context_id: [u8; 32],
    pub scenario: QualificationScenario,
    pub selector: QualificationFaultSelector,
    pub process_role: QualificationProcessRole,
    pub candidate_sha256: [u8; 32],
    pub release_tuple_v3_sha256: [u8; 32],
    pub source_revision: [u8; 20],
    pub namespace_sha256: [u8; 32],
    pub ticket_sha256: [u8; 32],
    pub nonce: [u8; 32],
    key_id: [u8; 32],
    signature: [u8; 64],
}

pub fn validate_admitted_shape(
    context: &RunContextWire,
    time_error: QualificationRunContextError,
) -> Result<AdmittedRunContextShape, QualificationRunContextError> {
    if context.schema_version != context_wire::SCHEMA_VERSION
        || context.signature.algorithm != "ed25519"
        || !crate::model::valid_run_id(&context.workflow_run_id)
    {
        return Err(QualificationRunContextError::InvalidContext);
    }
    let scenario = QualificationScenario::parse(&context.scenario_id)
        .ok_or(QualificationRunContextError::InvalidContext)?;
    let selector = QualificationFaultSelector::parse(&context.selector)
        .ok_or(QualificationRunContextError::InvalidContext)?;
    let process_role = QualificationProcessRole::parse(&context.process_role)
        .ok_or(QualificationRunContextError::InvalidContext)?;
    if selector.process_role() != process_role {
        return Err(QualificationRunContextError::InvalidContext);
    }
    valid_time_shape(context.issued_at, context.expires_at, time_error)?;
    Ok(AdmittedRunContextShape {
        context_id: decode_hex(&context.context_id)?,
        scenario,
        selector,
        process_role,
        candidate_sha256: decode_hex(&context.candidate_sha256)?,
        release_tuple_v3_sha256: decode_hex(&context.release_tuple_v3_sha256)?,
        source_revision: decode_hex(&context.source_revision)?,
        namespace_sha256: decode_hex(&context.namespace_sha256)?,
        ticket_sha256: decode_hex(&context.ticket_sha256)?,
        nonce: decode_base64url(&context.nonce)?,
        key_id: decode_hex(&context.signature.key_id)?,
        signature: decode_base64url(&context.signature.value)?,
    })
}

fn verify_context(
    context: &RunContextWire,
    expected: &QualificationRunContextExpectation,
    now: u64,
    policy: &ContextVerificationPolicy,
) -> Result<VerifiedQualificationRunContext, QualificationRunContextError> {
    let shape = validate_admitted_shape(context, QualificationRunContextError::InvalidTime)?;
    valid_freshness(context.issued_at, context.expires_at, now)?;
    if shape.key_id != policy.key_id {
        return Err(QualificationRunContextError::InvalidSignature);
    }
    policy
        .key
        .verify_strict(
            &context_wire::signing_payload(context)?,
            &Signature::from_bytes(&shape.signature),
        )
        .map_err(|_| QualificationRunContextError::InvalidSignature)?;
    if shape.scenario != expected.scenario
        || shape.selector != expected.selector
        || shape.process_role != expected.process_role
        || shape.candidate_sha256 != expected.candidate_sha256
        || shape.release_tuple_v3_sha256 != expected.release_tuple_v3_sha256
        || shape.source_revision != expected.source_revision
        || context.workflow_run_id != expected.workflow_run_id
        || shape.namespace_sha256 != expected.namespace_sha256
        || shape.ticket_sha256 != expected.ticket_sha256
    {
        return Err(QualificationRunContextError::BindingMismatch);
    }
    Ok(VerifiedQualificationRunContext::verified(
        shape.context_id,
        shape.nonce,
        context.expires_at,
        shape.ticket_sha256,
    ))
}

fn valid_time_shape(
    issued_at: u64,
    expires_at: u64,
    error: QualificationRunContextError,
) -> Result<(), QualificationRunContextError> {
    let lifetime = expires_at.checked_sub(issued_at);
    if issued_at > MAX_SAFE_JSON_INTEGER
        || expires_at > MAX_SAFE_JSON_INTEGER
        || lifetime.is_none_or(|value| value == 0 || value > MAX_CONTEXT_LIFETIME_SECONDS)
    {
        return Err(error);
    }
    Ok(())
}

const fn valid_freshness(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), QualificationRunContextError> {
    if now > MAX_SAFE_JSON_INTEGER || issued_at > now || expires_at <= now {
        return Err(QualificationRunContextError::InvalidTime);
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], QualificationRunContextError> {
    let bytes: [u8; N] = hex::decode(value)
        .ok()
        .and_then(|decoded| decoded.try_into().ok())
        .ok_or(QualificationRunContextError::InvalidContext)?;
    (hex::encode(bytes) == value)
        .then_some(bytes)
        .ok_or(QualificationRunContextError::InvalidContext)
}

fn decode_base64url<const N: usize>(value: &str) -> Result<[u8; N], QualificationRunContextError> {
    let bytes: [u8; N] = URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|decoded| decoded.try_into().ok())
        .ok_or(QualificationRunContextError::InvalidContext)?;
    (URL_SAFE_NO_PAD.encode(bytes) == value)
        .then_some(bytes)
        .ok_or(QualificationRunContextError::InvalidContext)
}
