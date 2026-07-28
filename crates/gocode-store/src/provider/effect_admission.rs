use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;

use gocode_application::provider::{
    ProviderAdmissionError, ProviderEffectAdmission, ProviderEffectAuthorityRecord,
    ProviderEffectAuthorityRef, ProviderEffectRequest,
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

/// SQLite implementation of atomic provider audit/budget/intent/permit admission.
pub struct SqliteProviderEffectAdmission {
    connection: Mutex<Connection>,
}

impl SqliteProviderEffectAdmission {
    /// Opens the shared runtime database and validates its exact schema.
    pub fn open(path: &Path) -> Result<Self, ProviderAdmissionError> {
        let path = path
            .to_str()
            .ok_or(ProviderAdmissionError::RepositoryFailure)?;
        let connection =
            open_with_pragmas(path).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        apply_migrations(&connection).map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        run_startup_gates(&connection, path)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Returns the number of provider pre-effect transactions.
    pub fn committed_count(&self) -> Result<u64, ProviderAdmissionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM security_dispatch_intents
                 WHERE intent_id LIKE 'provider:%'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        u64::try_from(count).map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Issues immutable, revision-bound authority before any provider effect.
    pub fn issue_authority(
        &self,
        record: &ProviderEffectAuthorityRecord,
    ) -> Result<(), ProviderAdmissionError> {
        validate_authority_record(record)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        if let Some(existing) = load_authority(&transaction, record.authority_ref)? {
            return if authority_matches_record(&existing, record) {
                Ok(())
            } else {
                Err(ProviderAdmissionError::AuthorityConflict)
            };
        }
        transaction
            .execute(
                "INSERT INTO provider_effect_authorities
                 (authority_id, revision, attempt_id, permit_id, capability_grant_id,
                  token_reservation_id, cost_reservation_id, prepared_digest, render_digest,
                  profile_digest, owner_id, scope, fencing_token, expires_at, revoked, consumed,
                  consumed_intent_id)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                         ?15, ?16, NULL)",
                params![
                    record.authority_ref.authority_id().as_slice(),
                    i64::try_from(record.authority_ref.revision())
                        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                    record.attempt_id.as_bytes().as_slice(),
                    record.permit_id.as_slice(),
                    record.capability_grant_id,
                    record.token_reservation_id.as_slice(),
                    record.cost_reservation_id.as_slice(),
                    record.prepared_digest.as_slice(),
                    record.render_digest.as_slice(),
                    record.profile_digest.as_slice(),
                    record.owner_id,
                    record.scope,
                    i64::try_from(record.fencing_token)
                        .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                    record.expires_at,
                    i64::from(record.revoked),
                    i64::from(record.consumed),
                ],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }
}

impl ProviderEffectAdmission for SqliteProviderEffectAdmission {
    fn admit(&self, request: &ProviderEffectRequest) -> Result<(), ProviderAdmissionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let authority = load_authority(&transaction, request.authority_ref)?
            .ok_or(ProviderAdmissionError::AuthorityDenied)?;
        verify_authority(&authority, request)?;

        let intent_id = format!("provider:{}", encode_hex(request.attempt_id.as_bytes()));

        if let Some(existing) = load_existing(&transaction, &intent_id)? {
            return if existing_matches_authority(&existing, &authority) {
                Ok(())
            } else {
                Err(ProviderAdmissionError::AuthorityConflict)
            };
        }
        if authority.consumed || authority.revoked || authority.expires_at <= unix_timestamp() {
            return Err(ProviderAdmissionError::AuthorityDenied);
        }
        let dispatch = load_dispatch_binding(&transaction, request)?;
        verify_dispatch_binding(&dispatch, request)?;
        if dispatch.state != 1 {
            return Err(ProviderAdmissionError::PostClaimUncertain);
        }
        consume_authority(&transaction, &authority, &intent_id)?;
        insert_pre_effect(&transaction, &intent_id, &authority)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
        Ok(())
    }
}

struct DispatchBinding {
    permit_id: [u8; 16],
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    fencing_token: u64,
    prepared_digest: [u8; 32],
    render_digest: [u8; 32],
    profile_digest: [u8; 32],
    state: i64,
}

struct Authority {
    authority_ref: ProviderEffectAuthorityRef,
    attempt_id: gocode_provider::DispatchAttemptId,
    permit_id: [u8; 16],
    capability_grant_id: String,
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
    prepared_digest: [u8; 32],
    render_digest: [u8; 32],
    profile_digest: [u8; 32],
    owner_id: String,
    scope: String,
    fencing_token: u64,
    expires_at: i64,
    revoked: bool,
    consumed: bool,
}

fn load_authority(
    transaction: &Transaction<'_>,
    authority_ref: ProviderEffectAuthorityRef,
) -> Result<Option<Authority>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT attempt_id, permit_id, capability_grant_id, token_reservation_id,
                    cost_reservation_id, prepared_digest, render_digest, profile_digest,
                    owner_id, scope, fencing_token, expires_at, revoked, consumed
             FROM provider_effect_authorities WHERE authority_id = ?1 AND revision = ?2",
            params![
                authority_ref.authority_id().as_slice(),
                i64::try_from(authority_ref.revision())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
            ],
            |row| {
                let fence: i64 = row.get(10)?;
                Ok(Authority {
                    authority_ref,
                    attempt_id: gocode_provider::DispatchAttemptId::from_bytes(fixed_bytes(
                        row.get(0)?,
                    )?),
                    permit_id: fixed_bytes(row.get(1)?)?,
                    capability_grant_id: row.get(2)?,
                    token_reservation_id: fixed_bytes(row.get(3)?)?,
                    cost_reservation_id: fixed_bytes(row.get(4)?)?,
                    prepared_digest: fixed_bytes(row.get(5)?)?,
                    render_digest: fixed_bytes(row.get(6)?)?,
                    profile_digest: fixed_bytes(row.get(7)?)?,
                    owner_id: row.get(8)?,
                    scope: row.get(9)?,
                    fencing_token: u64::try_from(fence)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    expires_at: row.get(11)?,
                    revoked: row.get::<_, i64>(12)? == 1,
                    consumed: row.get::<_, i64>(13)? == 1,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn verify_authority(
    authority: &Authority,
    request: &ProviderEffectRequest,
) -> Result<(), ProviderAdmissionError> {
    if authority.attempt_id != request.attempt_id
        || authority.permit_id != request.permit_id
        || authority.token_reservation_id != request.token_reservation_id
        || authority.cost_reservation_id != request.cost_reservation_id
        || authority.prepared_digest != request.prepared_digest
        || authority.render_digest != request.render_digest
        || authority.profile_digest != request.profile_digest
        || authority.fencing_token != request.fencing_token
        || authority.owner_id != request.owner_id
        || authority.scope != request.scope
    {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

fn consume_authority(
    transaction: &Transaction<'_>,
    authority: &Authority,
    intent_id: &str,
) -> Result<(), ProviderAdmissionError> {
    let changed = transaction
        .execute(
            "UPDATE provider_effect_authorities SET consumed = 1, consumed_intent_id = ?3
         WHERE authority_id = ?1 AND revision = ?2 AND consumed = 0 AND revoked = 0",
            params![
                authority.authority_ref.authority_id().as_slice(),
                i64::try_from(authority.authority_ref.revision())
                    .map_err(|_| ProviderAdmissionError::AuthorityDenied)?,
                intent_id,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(())
}

fn load_dispatch_binding(
    transaction: &Transaction<'_>,
    request: &ProviderEffectRequest,
) -> Result<DispatchBinding, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT permit_id, token_reservation_id, cost_reservation_id,
                    fencing_token, prepared_digest, render_digest, profile_digest, state
             FROM provider_dispatch_attempts WHERE attempt_id = ?1",
            [request.attempt_id.as_bytes().as_slice()],
            |row| {
                let fencing_token: i64 = row.get(3)?;
                Ok(DispatchBinding {
                    permit_id: fixed_bytes(row.get(0)?)?,
                    token_reservation_id: fixed_bytes(row.get(1)?)?,
                    cost_reservation_id: fixed_bytes(row.get(2)?)?,
                    fencing_token: u64::try_from(fencing_token)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    prepared_digest: fixed_bytes(row.get(4)?)?,
                    render_digest: fixed_bytes(row.get(5)?)?,
                    profile_digest: fixed_bytes(row.get(6)?)?,
                    state: row.get(7)?,
                })
            },
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn verify_dispatch_binding(
    stored: &DispatchBinding,
    request: &ProviderEffectRequest,
) -> Result<(), ProviderAdmissionError> {
    if stored.permit_id != request.permit_id {
        return Err(ProviderAdmissionError::PermitMismatch);
    }
    if stored.token_reservation_id != request.token_reservation_id {
        return Err(ProviderAdmissionError::TokenReservationMismatch);
    }
    if stored.cost_reservation_id != request.cost_reservation_id {
        return Err(ProviderAdmissionError::CostReservationMismatch);
    }
    if stored.fencing_token != request.fencing_token {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    if stored.prepared_digest != request.prepared_digest
        || stored.render_digest != request.render_digest
    {
        return Err(ProviderAdmissionError::RenderDigestMismatch);
    }
    if stored.profile_digest != request.profile_digest {
        return Err(ProviderAdmissionError::RenderDigestMismatch);
    }
    Ok(())
}

struct ExistingAdmission {
    grant_id: String,
    budget_binding: String,
    permit_id: String,
}

fn existing_matches_authority(existing: &ExistingAdmission, authority: &Authority) -> bool {
    existing.grant_id == authority.capability_grant_id
        && existing.budget_binding
            == format!(
                "provider:{}:{}",
                encode_hex(&authority.token_reservation_id),
                encode_hex(&authority.cost_reservation_id)
            )
        && existing.permit_id == encode_hex(&authority.permit_id)
}

fn authority_matches_record(authority: &Authority, record: &ProviderEffectAuthorityRecord) -> bool {
    authority.authority_ref == record.authority_ref
        && authority.attempt_id == record.attempt_id
        && authority.permit_id == record.permit_id
        && authority.capability_grant_id == record.capability_grant_id
        && authority.token_reservation_id == record.token_reservation_id
        && authority.cost_reservation_id == record.cost_reservation_id
        && authority.prepared_digest == record.prepared_digest
        && authority.render_digest == record.render_digest
        && authority.profile_digest == record.profile_digest
        && authority.owner_id == record.owner_id
        && authority.scope == record.scope
        && authority.fencing_token == record.fencing_token
        && authority.expires_at == record.expires_at
        && authority.revoked == record.revoked
        && authority.consumed == record.consumed
}

fn validate_authority_record(
    record: &ProviderEffectAuthorityRecord,
) -> Result<(), ProviderAdmissionError> {
    if record.authority_ref.authority_id() == [0; 16]
        || record.authority_ref.revision() == 0
        || record.fencing_token == 0
        || record.capability_grant_id.is_empty()
        || record.capability_grant_id.len() > 256
        || record.owner_id.is_empty()
        || record.owner_id.len() > 256
        || record.scope.is_empty()
        || record.scope.len() > 256
        || record
            .capability_grant_id
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || record.owner_id.bytes().any(|byte| byte.is_ascii_control())
        || record.scope.bytes().any(|byte| byte.is_ascii_control())
        || record.consumed
    {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    Ok(())
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
}

fn load_existing(
    transaction: &Transaction<'_>,
    intent_id: &str,
) -> Result<Option<ExistingAdmission>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT auth.grant_id, budget.reservation_id, permit.permit_id
             FROM security_dispatch_intents intent
             JOIN security_authorization_decisions auth USING (intent_id)
             JOIN security_budget_consumptions budget USING (intent_id)
             JOIN security_audit_pre_effect audit USING (intent_id)
             JOIN security_permit_claims permit USING (intent_id)
             WHERE intent.intent_id = ?1 AND intent.status = 'uncertain'
               AND auth.allowed = 1 AND audit.side_effect_started = 1",
            [intent_id],
            |row| {
                Ok(ExistingAdmission {
                    grant_id: row.get(0)?,
                    budget_binding: row.get(1)?,
                    permit_id: row.get(2)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn insert_pre_effect(
    transaction: &Transaction<'_>,
    intent_id: &str,
    authority: &Authority,
) -> Result<(), ProviderAdmissionError> {
    let budget_binding = format!(
        "provider:{}:{}",
        encode_hex(&authority.token_reservation_id),
        encode_hex(&authority.cost_reservation_id)
    );
    let permit_id = encode_hex(&authority.permit_id);
    transaction
        .execute(
            "INSERT INTO security_dispatch_intents (intent_id, status)
             VALUES (?1, 'uncertain')",
            [intent_id],
        )
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_authorization_decisions
                 (intent_id, grant_id, allowed, reason)
                 VALUES (?1, ?2, 1, 'provider-dispatch')",
                params![intent_id, authority.capability_grant_id],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_budget_consumptions
                 (intent_id, reservation_id, amount) VALUES (?1, ?2, 2)",
                params![intent_id, budget_binding],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_audit_pre_effect
                 (intent_id, side_effect_started) VALUES (?1, 1)",
                [intent_id],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_permit_claims (permit_id, intent_id)
                 VALUES (?1, ?2)",
                params![permit_id, intent_id],
            )
        })
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn fixed_bytes<const N: usize>(bytes: Vec<u8>) -> rusqlite::Result<[u8; N]> {
    bytes.try_into().map_err(|_| rusqlite::Error::InvalidQuery)
}
