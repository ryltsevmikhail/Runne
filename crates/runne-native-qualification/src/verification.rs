use std::collections::HashSet;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::Signature;

use crate::compiled_policy::{self, FaultVerificationPolicy};
use crate::model::{
    QualificationFaultContext, QualificationFaultError, QualificationFaultSelector,
    QualificationProcessRole, VerifiedQualificationFault, valid_run_id,
};
use crate::wire::{self, FaultTicketWire};

const MAX_TICKET_LIFETIME_SECONDS: u64 = 15 * 60;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;

/// Stateful verifier that consumes each valid ticket identifier and nonce once.
pub struct QualificationFaultVerifier {
    policy: Option<FaultVerificationPolicy>,
    consumed_ticket_ids: HashSet<[u8; 32]>,
    consumed_nonces: HashSet<[u8; 32]>,
}

impl QualificationFaultVerifier {
    /// Loads only the public authority embedded at compile time.
    #[must_use]
    pub fn from_compiled_policy() -> Self {
        Self::with_policy(compiled_policy::load())
    }

    fn with_policy(policy: Option<FaultVerificationPolicy>) -> Self {
        Self {
            policy,
            consumed_ticket_ids: HashSet::new(),
            consumed_nonces: HashSet::new(),
        }
    }

    /// Verifies exact ticket bindings and consumes its replay identities.
    ///
    /// # Errors
    ///
    /// Fails closed if compile-time policy is unavailable or any wire,
    /// signature, time, context, role, selector, or replay check fails.
    pub fn verify_and_consume(
        &mut self,
        bytes: &[u8],
        context: &QualificationFaultContext,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationFault, QualificationFaultError> {
        let policy = self
            .policy
            .as_ref()
            .ok_or(QualificationFaultError::PolicyUnavailable)?;
        let ticket = wire::decode(bytes)?;
        let verified = verify_ticket(&ticket, context, now_unix_seconds, policy)?;
        if self.consumed_ticket_ids.contains(&verified.ticket_id)
            || self.consumed_nonces.contains(&verified.nonce)
        {
            return Err(QualificationFaultError::Replay);
        }
        self.consumed_ticket_ids.insert(verified.ticket_id);
        self.consumed_nonces.insert(verified.nonce);
        Ok(verified)
    }

    #[cfg(test)]
    pub(super) fn for_test(key: ed25519_dalek::VerifyingKey) -> Self {
        use sha2::{Digest as _, Sha256};
        let key_id = Sha256::digest(key.as_bytes()).into();
        Self::with_policy(Some(FaultVerificationPolicy { key, key_id }))
    }
}

fn verify_ticket(
    ticket: &FaultTicketWire,
    context: &QualificationFaultContext,
    now: u64,
    policy: &FaultVerificationPolicy,
) -> Result<VerifiedQualificationFault, QualificationFaultError> {
    let shape = validate_admitted_shape(ticket, QualificationFaultError::InvalidTime)?;
    valid_freshness(ticket.issued_at, ticket.expires_at, now)?;
    verify_signature(ticket, policy, &shape)?;
    if shape.selector != context.selector
        || shape.process_role != context.process_role
        || shape.candidate_sha256 != context.candidate_sha256
        || shape.release_tuple_v3_sha256 != context.release_tuple_v3_sha256
        || shape.source_revision != context.source_revision
        || ticket.workflow_run_id != context.workflow_run_id
        || shape.namespace_sha256 != context.namespace_sha256
    {
        return Err(QualificationFaultError::ContextMismatch);
    }
    Ok(VerifiedQualificationFault {
        selector: shape.selector,
        process_role: shape.process_role,
        ticket_id: shape.ticket_id,
        nonce: shape.nonce,
        expires_at: ticket.expires_at,
    })
}

pub struct AdmittedFaultTicketShape {
    selector: QualificationFaultSelector,
    process_role: QualificationProcessRole,
    ticket_id: [u8; 32],
    candidate_sha256: [u8; 32],
    release_tuple_v3_sha256: [u8; 32],
    source_revision: [u8; 20],
    namespace_sha256: [u8; 32],
    nonce: [u8; 32],
    key_id: [u8; 32],
    signature: [u8; 64],
}

pub fn validate_admitted_shape(
    ticket: &FaultTicketWire,
    time_error: QualificationFaultError,
) -> Result<AdmittedFaultTicketShape, QualificationFaultError> {
    if ticket.schema_version != wire::SCHEMA_VERSION
        || ticket.signature.algorithm != "ed25519"
        || !valid_run_id(&ticket.workflow_run_id)
    {
        return Err(QualificationFaultError::InvalidTicket);
    }
    let selector = QualificationFaultSelector::parse(&ticket.selector)
        .ok_or(QualificationFaultError::InvalidTicket)?;
    let process_role = QualificationProcessRole::parse(&ticket.process_role)
        .ok_or(QualificationFaultError::InvalidTicket)?;
    if selector.process_role() != process_role {
        return Err(QualificationFaultError::InvalidTicket);
    }
    valid_time_shape(ticket.issued_at, ticket.expires_at, time_error)?;
    Ok(AdmittedFaultTicketShape {
        selector,
        process_role,
        ticket_id: decode_hex::<32>(&ticket.ticket_id)?,
        candidate_sha256: decode_hex::<32>(&ticket.candidate_sha256)?,
        release_tuple_v3_sha256: decode_hex::<32>(&ticket.release_tuple_v3_sha256)?,
        source_revision: decode_hex::<20>(&ticket.source_revision)?,
        namespace_sha256: decode_hex::<32>(&ticket.namespace_sha256)?,
        nonce: decode_base64url::<32>(&ticket.nonce)?,
        key_id: decode_hex::<32>(&ticket.signature.key_id)?,
        signature: decode_base64url::<64>(&ticket.signature.value)?,
    })
}

fn verify_signature(
    ticket: &FaultTicketWire,
    policy: &FaultVerificationPolicy,
    shape: &AdmittedFaultTicketShape,
) -> Result<(), QualificationFaultError> {
    if shape.key_id != policy.key_id {
        return Err(QualificationFaultError::InvalidSignature);
    }
    policy
        .key
        .verify_strict(
            &wire::signing_payload(ticket)?,
            &Signature::from_bytes(&shape.signature),
        )
        .map_err(|_| QualificationFaultError::InvalidSignature)
}

fn valid_time_shape(
    issued_at: u64,
    expires_at: u64,
    error: QualificationFaultError,
) -> Result<(), QualificationFaultError> {
    let lifetime = expires_at.checked_sub(issued_at);
    if issued_at > MAX_SAFE_JSON_INTEGER
        || expires_at > MAX_SAFE_JSON_INTEGER
        || lifetime.is_none_or(|value| value == 0 || value > MAX_TICKET_LIFETIME_SECONDS)
    {
        return Err(error);
    }
    Ok(())
}

const fn valid_freshness(
    issued_at: u64,
    expires_at: u64,
    now: u64,
) -> Result<(), QualificationFaultError> {
    if now > MAX_SAFE_JSON_INTEGER || issued_at > now || expires_at <= now {
        return Err(QualificationFaultError::InvalidTime);
    }
    Ok(())
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], QualificationFaultError> {
    let bytes: [u8; N] = hex::decode(value)
        .ok()
        .and_then(|decoded| decoded.try_into().ok())
        .ok_or(QualificationFaultError::InvalidTicket)?;
    (hex::encode(bytes) == value)
        .then_some(bytes)
        .ok_or(QualificationFaultError::InvalidTicket)
}

fn decode_base64url<const N: usize>(value: &str) -> Result<[u8; N], QualificationFaultError> {
    let bytes: [u8; N] = URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .and_then(|decoded| decoded.try_into().ok())
        .ok_or(QualificationFaultError::InvalidTicket)?;
    (URL_SAFE_NO_PAD.encode(bytes) == value)
        .then_some(bytes)
        .ok_or(QualificationFaultError::InvalidTicket)
}
