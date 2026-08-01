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
