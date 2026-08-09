use gocode_application::provider::ProviderAdmissionError;
use std::time::{Duration, Instant};

use crate::schema::ManagedConnection;
use gocode_provider::ProviderDispatchClaim;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

/// Durable result of the one-shot pre-effect compare-and-swap.
///
/// ```compile_fail
/// use gocode_store::provider::ProviderEffectStartReceipt;
///
/// fn duplicate(receipt: ProviderEffectStartReceipt) {
///     let _ = receipt.clone();
/// }
/// ```
#[derive(PartialEq, Eq)]
pub struct ProviderEffectStartReceipt {
    expires_at: i64,
    attempt_id: [u8; 16],
    permit_id: [u8; 16],
    provider_idempotency_key: String,
    prepared_digest: [u8; 32],
    render_digest: [u8; 32],
    profile_digest: [u8; 32],
    fencing_token: u64,
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    deadline: Instant,
}

impl std::fmt::Debug for ProviderEffectStartReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderEffectStartReceipt")
            .field("expires_at", &self.expires_at)
            .field("binding", &"<redacted>")
            .field("deadline", &"<monotonic>")
            .finish()
    }
}

impl ProviderEffectStartReceipt {
    /// Absolute Unix-second effect expiry loaded after the committed CAS.
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the single monotonic deadline captured after durable readback.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns whether this receipt is bound to the exact admitted claim.
    pub fn matches_claim(&self, claim: &ProviderDispatchClaim) -> bool {
        self.attempt_id == *claim.attempt_id.as_bytes()
            && self.permit_id == claim.permit_id
            && self.provider_idempotency_key == claim.provider_idempotency_key
            && self.prepared_digest == claim.prepared_digest
            && self.render_digest == claim.render_digest
            && self.profile_digest == claim.profile_digest
            && self.fencing_token == claim.fencing_token
            && self.token_reservation_id == claim.token_reservation_id
            && self.cost_reservation_id == claim.cost_reservation_id
    }
}

pub(super) fn start_effect(
    connection: &mut ManagedConnection,
    claim: &ProviderDispatchClaim,
    wall_before: i64,
    wall_after: impl FnOnce() -> i64,
    fail_readback: bool,
) -> Result<ProviderEffectStartReceipt, ProviderAdmissionError> {
    let expires_at = wall_before
        .checked_add(120)
        .ok_or(ProviderAdmissionError::AuthorityDenied)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    let valid = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1
            FROM provider_execution_admissions admission
            JOIN provider_dispatch_attempts dispatch
              ON dispatch.attempt_id = admission.dispatch_attempt_id
            JOIN provider_runtime_authority_state runtime ON runtime.id = 1
            JOIN provider_effect_authorities authority
              ON authority.authority_id = admission.authority_id
             AND authority.revision = admission.authority_revision
            WHERE admission.dispatch_attempt_id = ?1 AND admission.permit_id = ?2
              AND admission.provider_idempotency_key = ?3
              AND admission.prepared_digest = ?4 AND admission.render_digest = ?5
              AND admission.profile_digest = ?6 AND admission.fencing_token = ?7
              AND admission.token_reservation_id = ?9 AND admission.cost_reservation_id = ?10
              AND dispatch.state = 1 AND dispatch.permit_id = ?2
              AND dispatch.prepared_digest = ?4 AND dispatch.render_digest = ?5
              AND dispatch.profile_digest = ?6 AND dispatch.fencing_token = ?7
              AND dispatch.token_reservation_id = ?9 AND dispatch.cost_reservation_id = ?10
              AND runtime.active = 1
              AND runtime.expected_generation = runtime.lease_generation
              AND runtime.expected_fencing_token = runtime.lease_fencing_token
              AND runtime.runtime_authority_id = admission.runtime_authority_id
              AND runtime.database_generation = admission.database_generation
              AND runtime.expected_generation = admission.generation
              AND runtime.expected_fencing_token = admission.fencing_token
              AND runtime.principal_id = admission.principal_id
              AND runtime.owner_id = admission.owner_id AND runtime.scope = admission.scope
              AND runtime.capability_grant_id = admission.capability_grant_id
              AND runtime.capability_revision = admission.capability_revision
              AND runtime.capability_expires_at = admission.capability_expires_at
              AND runtime.capability_revocation_epoch = admission.capability_revocation_epoch
              AND runtime.capability_revocation_observed = admission.capability_revocation_observed
              AND runtime.approval_id = admission.approval_id
              AND runtime.approval_revision = admission.approval_revision
              AND runtime.approval_expires_at = admission.approval_expires_at
              AND runtime.approval_revocation_epoch = admission.approval_revocation_epoch
              AND runtime.approval_revocation_observed = admission.approval_revocation_observed
              AND runtime.profile_digest = admission.profile_digest
              AND runtime.pricing_revision_digest = admission.pricing_revision_digest
              AND runtime.activation_binding_kind = admission.activation_binding_kind
              AND runtime.activation_binding_digest = admission.activation_binding_digest
              AND runtime.capability_allowed = 1 AND runtime.approval_allowed = 1
              AND runtime.capability_expires_at > ?8 AND runtime.approval_expires_at > ?8
              AND authority.attempt_id = admission.dispatch_attempt_id
              AND authority.permit_id = admission.permit_id
              AND authority.token_reservation_id = admission.token_reservation_id
              AND authority.cost_reservation_id = admission.cost_reservation_id
              AND authority.prepared_digest = admission.prepared_digest
              AND authority.render_digest = admission.render_digest
              AND authority.profile_digest = admission.profile_digest
              AND authority.owner_id = admission.owner_id AND authority.scope = admission.scope
              AND authority.fencing_token = admission.fencing_token
              AND authority.expires_at > ?8 AND authority.revoked = 0 AND authority.consumed = 1
              AND authority.consumed_intent_id = ('provider:' || lower(hex(admission.dispatch_attempt_id)))
              AND EXISTS(SELECT 1 FROM provider_budget_reservations b
                         WHERE b.provider_idempotency_key = admission.provider_idempotency_key
                           AND b.dimension = 1 AND b.reservation_id = admission.token_reservation_id
                           AND b.state = 1)
              AND EXISTS(SELECT 1 FROM provider_budget_reservations b
                         WHERE b.provider_idempotency_key = admission.provider_idempotency_key
                           AND b.dimension = 2 AND b.reservation_id = admission.cost_reservation_id
                           AND b.state = 1)
        )",
        params![
            claim.attempt_id.as_bytes().as_slice(), claim.permit_id.as_slice(),
            claim.provider_idempotency_key, claim.prepared_digest.as_slice(),
            claim.render_digest.as_slice(), claim.profile_digest.as_slice(),
            i64::try_from(claim.fencing_token).map_err(|_| ProviderAdmissionError::StaleFencingToken)?, wall_before,
            claim.token_reservation_id.as_slice(), claim.cost_reservation_id.as_slice(),
        ], |row| row.get::<_, bool>(0),
    ).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if !valid {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    let changed = transaction
        .execute(
            "INSERT INTO provider_effect_starts (
             dispatch_attempt_id, provider_idempotency_key, permit_id,
             effect_started_at, effect_expires_at, state
         ) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.provider_idempotency_key,
                claim.permit_id.as_slice(),
                wall_before,
                expires_at
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    let intent_id = format!("provider:{}", encode_hex(claim.attempt_id.as_bytes()));
    transaction
        .execute(
            "INSERT INTO security_audit_pre_effect (intent_id, side_effect_started) VALUES (?1, 1)",
            [&intent_id],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .commit()
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
    if fail_readback {
        return Err(ProviderAdmissionError::PostClaimUncertain);
    }
    let wall_after = wall_after();
    connection
        .query_row(
            "SELECT effect_started_at, effect_expires_at FROM provider_effect_starts
         WHERE dispatch_attempt_id = ?1 AND permit_id = ?2 AND effect_started_at = ?3
           AND effect_expires_at = ?4 AND state = 1",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                wall_before,
                expires_at
            ],
            |row| {
                let effective_wall = wall_before.max(wall_after).max(row.get::<_, i64>(0)?);
                let effect_expires_at = row.get::<_, i64>(1)?;
                let remaining = effect_expires_at
                    .checked_sub(effective_wall)
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                let remaining =
                    u64::try_from(remaining).map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderEffectStartReceipt {
                    expires_at: effect_expires_at,
                    attempt_id: *claim.attempt_id.as_bytes(),
                    permit_id: claim.permit_id,
                    provider_idempotency_key: claim.provider_idempotency_key.clone(),
                    prepared_digest: claim.prepared_digest,
                    render_digest: claim.render_digest,
                    profile_digest: claim.profile_digest,
                    fencing_token: claim.fencing_token,
                    token_reservation_id: claim.token_reservation_id,
                    cost_reservation_id: claim.cost_reservation_id,
                    deadline: Instant::now() + Duration::from_secs(remaining.min(120)),
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?
        .ok_or(ProviderAdmissionError::PostClaimUncertain)
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut text, byte| {
            use core::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        })
}
