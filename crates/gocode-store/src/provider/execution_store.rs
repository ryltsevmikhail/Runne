use std::fmt::Write as _;
use std::path::Path;
use std::sync::Mutex;

use gocode_application::provider::{
    ProviderAdmissionError, ProviderAuthorityIssueRequest, ProviderAuthorityIssuerDecision,
    ProviderEffectAuthorityRef, ProviderEncryptedPayload, ProviderExecutionError,
    ProviderExecutionStore, ProviderJournalAppendOutcome, ProviderJournalAppendRequest,
    ProviderJournalKeyBinding, ProviderPollRequest, ProviderTerminalCommitOutcome,
    ProviderTerminalOutboxRecord, ProviderTerminalPricingBinding, RuntimeProviderAuthorityIssuer,
};
use gocode_domain::id::{AttemptId, ConversationId, TaskRunId};
use gocode_provider::{
    DispatchAttemptId, ProviderCallDigestVersion, ProviderDispatchClaim, ProviderRepositoryState,
};
use gocode_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};
use rand::RngCore;
use rand::rngs::OsRng;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest, Sha256};

use crate::schema::{apply_migrations, open_with_pragmas, run_startup_gates};

const PROVIDER_EXECUTION_SEMANTIC_V1: &[u8] = b"GOCODE_PROVIDER_EXECUTION_SEMANTIC_V1\0";

/// Runtime-owned provider authority and budget state installed at startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRuntimeAuthorityConfig {
    /// Stable runtime authority identity.
    pub runtime_authority_id: [u8; 16],
    /// Current authoritative database generation.
    pub database_generation: u64,
    /// Authenticated principal accepted for this local runtime.
    pub principal_id: String,
    /// Runtime-derived effect owner.
    pub owner_id: String,
    /// Runtime-derived provider effect scope.
    pub scope: String,
    /// Expected worker generation.
    pub generation: u64,
    /// Expected worker fencing token.
    pub fencing_token: u64,
    /// Durable capability grant identity.
    pub capability_grant_id: String,
    /// Exact capability revision.
    pub capability_revision: u64,
    /// Current capability decision.
    pub capability_allowed: bool,
    /// Durable approval identity.
    pub approval_id: String,
    /// Exact approval revision.
    pub approval_revision: u64,
    /// Current approval decision.
    pub approval_allowed: bool,
    /// Inclusive Unix expiry for the approval.
    pub approval_expires_at: i64,
    /// Exact immutable provider profile.
    pub profile_digest: [u8; 32],
    /// Exact immutable pricing revision.
    pub pricing_revision_digest: [u8; 32],
    /// Durable aggregate token budget.
    pub token_budget_limit: u64,
    /// Durable aggregate worst-case cost budget.
    pub cost_budget_limit_micros: u64,
    /// Maximum issued authority lifetime.
    pub authority_ttl_seconds: u64,
}

impl ProviderRuntimeAuthorityConfig {
    fn validate(&self) -> Result<(), ProviderAdmissionError> {
        if self.runtime_authority_id == [0; 16]
            || self.database_generation == 0
            || self.generation == 0
            || self.fencing_token == 0
            || self.capability_revision == 0
            || self.approval_revision == 0
            || !(1..=300).contains(&self.authority_ttl_seconds)
            || !bounded_text(&self.principal_id)
            || !bounded_text(&self.owner_id)
            || !bounded_text(&self.scope)
            || !bounded_text(&self.capability_grant_id)
            || !bounded_text(&self.approval_id)
            || as_i64(self.database_generation).is_err()
            || as_i64(self.generation).is_err()
            || as_i64(self.fencing_token).is_err()
            || as_i64(self.capability_revision).is_err()
            || as_i64(self.approval_revision).is_err()
            || as_i64(self.token_budget_limit).is_err()
            || as_i64(self.cost_budget_limit_micros).is_err()
        {
            return Err(ProviderAdmissionError::InvalidSemanticContext);
        }
        Ok(())
    }
}

/// SQLite runtime-owned atomic provider authority issuer.
pub struct SqliteProviderExecutionStore {
    connection: Mutex<Connection>,
}

impl SqliteProviderExecutionStore {
    /// Opens the authoritative runtime database and validates schema V13.
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

    /// Installs or advances runtime-owned authority state.
    ///
    /// Aggregate settled and reserved budgets survive authority refresh.
    /// Generation rollback and same-generation fence replacement fail closed.
    pub fn install_runtime_authority(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        config.validate()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        install_runtime_authority_in_transaction(&transaction, config)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Installs runtime authority, freezes attempts owned by an older worker
    /// lease, and advances the lease in one crash-safe transaction.
    pub fn install_runtime_authority_and_advance_worker_lease(
        &self,
        config: &ProviderRuntimeAuthorityConfig,
    ) -> Result<(), ProviderAdmissionError> {
        config.validate()?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        install_runtime_authority_in_transaction(&transaction, config)?;
        advance_worker_lease_in_transaction(&transaction, config.generation, config.fencing_token)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Advances only the worker lease projection, used by supervisor recovery.
    ///
    /// Issuance freezes until a matching authority state is installed.
    pub fn advance_worker_lease(
        &self,
        generation: u64,
        fencing_token: u64,
    ) -> Result<(), ProviderAdmissionError> {
        if generation == 0 || fencing_token == 0 {
            return Err(ProviderAdmissionError::StaleFencingToken);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        advance_worker_lease_in_transaction(&transaction, generation, fencing_token)?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }

    /// Returns the number of atomically admitted provider executions.
    pub fn admitted_count(&self) -> Result<u64, ProviderAdmissionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM provider_execution_admissions",
                [],
                |row| row.get(0),
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        u64::try_from(count).map_err(|_| ProviderAdmissionError::RepositoryFailure)
    }
}

impl RuntimeProviderAuthorityIssuer for SqliteProviderExecutionStore {
    fn issue_decision(
        &self,
        request: &ProviderAuthorityIssueRequest,
    ) -> Result<ProviderAuthorityIssuerDecision, ProviderAdmissionError> {
        request.validate()?;
        let semantic_digest = execution_semantic_digest(request);
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;

        if let Some(existing) =
            load_existing_admission(&transaction, &request.provider_idempotency_key)?
        {
            return if existing.semantic_digest == semantic_digest {
                Ok(ProviderAuthorityIssuerDecision::existing(existing.state))
            } else {
                Err(ProviderAdmissionError::AuthorityConflict)
            };
        }

        let state =
            load_runtime_authority(&transaction)?.ok_or(ProviderAdmissionError::AuthorityDenied)?;
        verify_runtime_authority(&state, request)?;
        verify_prepared(&transaction, request)?;
        ensure_call_is_unclaimed(&transaction, request.prepared.call_id)?;

        let requested_tokens = request
            .requested_input_tokens
            .checked_add(request.requested_output_tokens)
            .ok_or(ProviderAdmissionError::TokenBudgetDenied)?;
        let available_tokens = state
            .token_budget_limit
            .checked_sub(state.token_budget_reserved)
            .and_then(|available| available.checked_sub(state.token_budget_settled))
            .ok_or(ProviderAdmissionError::TokenBudgetDenied)?;
        if requested_tokens > available_tokens {
            return Err(ProviderAdmissionError::TokenBudgetDenied);
        }
        let available_cost = state
            .cost_budget_limit_micros
            .checked_sub(state.cost_budget_reserved_micros)
            .and_then(|available| available.checked_sub(state.cost_budget_settled_micros))
            .ok_or(ProviderAdmissionError::CostBudgetDenied)?;
        if request.max_cost_micros > available_cost {
            return Err(ProviderAdmissionError::CostBudgetDenied);
        }

        let ids = IssuedIds::random();
        let now = unix_timestamp();
        let ttl = i64::try_from(state.authority_ttl_seconds)
            .map_err(|_| ProviderAdmissionError::AuthorityDenied)?;
        let expires_at = now
            .checked_add(ttl)
            .map(|expiry| expiry.min(state.approval_expires_at))
            .filter(|expiry| *expiry > now)
            .ok_or(ProviderAdmissionError::ApprovalExpired)?;
        let claim = ProviderDispatchClaim {
            call_id: request.prepared.call_id,
            attempt_id: DispatchAttemptId::from_bytes(ids.dispatch_attempt_id),
            permit_id: ids.permit_id,
            prepared_digest: request.prepared.prepared_digest,
            render_digest: request.prepared.render_digest,
            profile_digest: request.prepared.profile_digest,
            token_reservation_id: ids.token_reservation_id,
            cost_reservation_id: ids.cost_reservation_id,
            fencing_token: state.expected_fencing_token,
            provider_idempotency_key: request.provider_idempotency_key.clone(),
        };
        let authority_ref =
            ProviderEffectAuthorityRef::new(ids.authority_id, state.state_revision)?;
        commit_issuance(
            &transaction,
            request,
            &state,
            &claim,
            authority_ref,
            semantic_digest,
            requested_tokens,
            now,
            expires_at,
        )?;
        transaction
            .commit()
            .map_err(|_| ProviderAdmissionError::PostClaimUncertain)?;
        ProviderAuthorityIssuerDecision::from_durable_commit(
            request,
            authority_ref,
            state.expected_generation,
            claim,
        )
    }
}

impl ProviderExecutionStore for SqliteProviderExecutionStore {
    fn active_journal_key_binding(
        &self,
    ) -> Result<Option<ProviderJournalKeyBinding>, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        load_active_journal_key(&connection).map(|record| record.map(|record| record.binding))
    }

    fn activate_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let runtime = load_runtime_authority(&transaction)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .ok_or(ProviderExecutionError::JournalKeyUnavailable)?;
        if key.runtime_authority_id() != runtime.runtime_authority_id
            || key.database_generation() != runtime.database_generation
        {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        if let Some(stored) = load_journal_key_state(&transaction, key)? {
            if stored == JournalKeyState::Active {
                return Ok(());
            }
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        if let Some(active) = load_active_journal_key(&transaction)? {
            if key.key_version() <= active.binding.key_version() {
                return Err(ProviderExecutionError::JournalKeyUnavailable);
            }
            transaction
                .execute(
                    "UPDATE provider_journal_key_refs
                     SET state = 2, active_slot = NULL, retired_at = ?3
                     WHERE key_id = ?1 AND key_version = ?2
                       AND state = 1 AND active_slot = 1",
                    params![
                        active.binding.key_id().as_slice(),
                        execution_i64(active.binding.key_version())?,
                        unix_timestamp(),
                    ],
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        }
        transaction
            .execute(
                "INSERT INTO provider_journal_key_refs (
                    key_id, key_version, runtime_authority_id, database_generation,
                    state, active_slot, created_at, retired_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, 1, ?5, NULL)",
                params![
                    key.key_id().as_slice(),
                    execution_i64(key.key_version())?,
                    key.runtime_authority_id().as_slice(),
                    execution_i64(key.database_generation())?,
                    unix_timestamp(),
                ],
            )
            .map_err(|_| ProviderExecutionError::JournalKeyUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

    fn journal_key_reference_count(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<u64, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        ensure_journal_key_exists(&connection, key)?;
        let count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces
                 WHERE key_id = ?1 AND key_version = ?2",
                params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        u64::try_from(count).map_err(|_| ProviderExecutionError::JournalCorrupt)
    }

    fn remove_retired_journal_key(
        &self,
        key: ProviderJournalKeyBinding,
    ) -> Result<(), ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if load_journal_key_state(&transaction, key)? != Some(JournalKeyState::Retired) {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        let references: i64 = transaction
            .query_row(
                "SELECT COUNT(*) FROM provider_encryption_nonces
                 WHERE key_id = ?1 AND key_version = ?2",
                params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if references != 0 {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        let changed = transaction
            .execute(
                "DELETE FROM provider_journal_key_refs
                 WHERE key_id = ?1 AND key_version = ?2 AND state = 2",
                params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::JournalKeyUnavailable);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

    fn begin_provider_poll(
        &self,
        request: &ProviderPollRequest,
    ) -> Result<(), ProviderExecutionError> {
        validate_poll_request(request)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id)?;
        verify_attempt_for_progress(
            &attempt,
            request.fencing_token,
            request.runtime_generation,
            request.profile_digest,
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if attempt.state != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let next_sequence = next_journal_sequence(&transaction, request.attempt_id)?;
        if request.cursor != next_sequence {
            return Err(ProviderExecutionError::SequenceMismatch);
        }
        let existing = transaction
            .query_row(
                "SELECT cursor, runtime_generation, fencing_token
                 FROM provider_poll_flights WHERE dispatch_attempt_id = ?1",
                [request.attempt_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        nonnegative_u64(row.get(0)?)?,
                        positive_u64(row.get(1)?)?,
                        positive_u64(row.get(2)?)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if existing.is_some() {
            let changed = transaction
                .execute(
                    "UPDATE provider_dispatch_attempts SET state = 6
                     WHERE attempt_id = ?1 AND state = 3",
                    [request.attempt_id.as_bytes().as_slice()],
                )
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            if changed != 1 {
                return Err(ProviderExecutionError::AttemptUncertain);
            }
            transaction
                .commit()
                .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        transaction
            .execute(
                "INSERT INTO provider_poll_flights (
                    dispatch_attempt_id, cursor, runtime_generation, fencing_token, opened_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.cursor)?,
                    execution_i64(request.runtime_generation)?,
                    execution_i64(request.fencing_token)?,
                    unix_timestamp(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

    fn append_encrypted_event(
        &self,
        request: &ProviderJournalAppendRequest,
    ) -> Result<ProviderJournalAppendOutcome, ProviderExecutionError> {
        validate_journal_append(request)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id)?;
        verify_attempt_for_progress(
            &attempt,
            request.fencing_token,
            request.runtime_generation,
            request.profile_digest,
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if attempt.state != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if attempt.call_digest_version != request.call_digest_version {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        ensure_active_journal_key(&transaction, request.key, &attempt)?;

        if let Some(existing) =
            load_encrypted_event(&transaction, request.attempt_id, request.sequence)?
        {
            return if existing == *request {
                Ok(ProviderJournalAppendOutcome::Replayed)
            } else {
                Err(ProviderExecutionError::JournalCorrupt)
            };
        }
        let armed: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provider_poll_flights
                    WHERE dispatch_attempt_id = ?1 AND cursor = ?2
                      AND runtime_generation = ?3 AND fencing_token = ?4
                 )",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.sequence)?,
                    execution_i64(request.runtime_generation)?,
                    execution_i64(request.fencing_token)?,
                ],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if !armed {
            return Err(ProviderExecutionError::PollNotArmed);
        }
        let next_sequence = next_journal_sequence(&transaction, request.attempt_id)?;
        if request.sequence != next_sequence {
            return Err(ProviderExecutionError::SequenceMismatch);
        }
        let terminal_exists: bool = transaction
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM provider_stream_journal
                    WHERE dispatch_attempt_id = ?1 AND terminal = 1
                 )",
                [request.attempt_id.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if terminal_exists {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        insert_nonce(
            &transaction,
            request.key,
            request.encrypted.nonce(),
            1,
            request.attempt_id,
            Some(request.sequence),
        )?;
        transaction
            .execute(
                "INSERT INTO provider_stream_journal (
                    dispatch_attempt_id, sequence, key_id, key_version, nonce,
                    call_digest_version, profile_digest, runtime_generation,
                    event_kind, terminal, ciphertext, plaintext_len, plaintext_digest
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.sequence)?,
                    request.key.key_id().as_slice(),
                    execution_i64(request.key.key_version())?,
                    request.encrypted.nonce().as_slice(),
                    encode_call_digest_version(request.call_digest_version),
                    request.profile_digest.as_slice(),
                    execution_i64(request.runtime_generation)?,
                    i64::from(request.event_kind),
                    i64::from(request.terminal),
                    request.encrypted.ciphertext(),
                    execution_i64(request.encrypted.plaintext_len())?,
                    request.encrypted.plaintext_digest().as_slice(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let closed = transaction
            .execute(
                "DELETE FROM provider_poll_flights
                 WHERE dispatch_attempt_id = ?1 AND cursor = ?2
                   AND runtime_generation = ?3 AND fencing_token = ?4",
                params![
                    request.attempt_id.as_bytes().as_slice(),
                    execution_i64(request.sequence)?,
                    execution_i64(request.runtime_generation)?,
                    execution_i64(request.fencing_token)?,
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if closed != 1 {
            return Err(ProviderExecutionError::PollNotArmed);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(ProviderJournalAppendOutcome::Inserted)
    }

    fn load_encrypted_events(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<Vec<ProviderJournalAppendRequest>, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&connection, attempt_id)?;
        let mut statement = connection
            .prepare(
                "SELECT journal.sequence, journal.key_id, journal.key_version,
                        keys.runtime_authority_id, keys.database_generation,
                        journal.nonce, journal.call_digest_version, journal.profile_digest,
                        journal.runtime_generation, journal.event_kind, journal.terminal,
                        journal.ciphertext, journal.plaintext_len, journal.plaintext_digest
                 FROM provider_stream_journal journal
                 JOIN provider_journal_key_refs keys
                   ON keys.key_id = journal.key_id AND keys.key_version = journal.key_version
                 WHERE journal.dispatch_attempt_id = ?1
                 ORDER BY journal.sequence",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let rows = statement
            .query_map([attempt_id.as_bytes().as_slice()], |row| {
                let sequence = nonnegative_u64(row.get(0)?)?;
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(1)?)?,
                    positive_u64(row.get(2)?)?,
                    fixed_bytes(row.get(3)?)?,
                    positive_u64(row.get(4)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(5)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderJournalAppendRequest {
                    attempt_id,
                    fencing_token: attempt.fencing_token,
                    sequence,
                    event_kind: u8::try_from(row.get::<_, i64>(9)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    terminal: decode_bool(row.get(10)?)?,
                    call_digest_version: decode_call_digest_version(row.get(6)?)?,
                    profile_digest: fixed_bytes(row.get(7)?)?,
                    runtime_generation: positive_u64(row.get(8)?)?,
                    key,
                    encrypted,
                })
            })
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
        for (expected, row) in rows.iter().enumerate() {
            if row.sequence != expected as u64
                || row.profile_digest != attempt.profile_digest
                || row.runtime_generation != attempt.generation
                || row.call_digest_version != attempt.call_digest_version
                || row.key.runtime_authority_id() != attempt.runtime_authority_id
                || row.key.database_generation() != attempt.database_generation
            {
                return Err(ProviderExecutionError::JournalCorrupt);
            }
        }
        Ok(rows)
    }

    fn load_terminal_pricing_binding(
        &self,
        attempt_id: DispatchAttemptId,
    ) -> Result<ProviderTerminalPricingBinding, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&connection, attempt_id)?;
        verify_current_runtime_lease(&connection, &attempt)?;
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if !matches!(attempt.state, 3..=5) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        ProviderTerminalPricingBinding::with_reservation(
            attempt.pricing_revision_digest,
            attempt.currency,
            attempt.requested_input_tokens,
            attempt.requested_output_tokens,
            attempt.max_cost_micros,
        )
    }

    fn pending_terminal_outbox(
        &self,
    ) -> Result<Vec<ProviderTerminalOutboxRecord>, ProviderExecutionError> {
        let connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let mut statement = connection
            .prepare(
                "SELECT outbox.outbox_id, outbox.dispatch_attempt_id,
                        outbox.terminal_sequence, outbox.call_digest_version,
                        outbox.key_id, outbox.key_version, keys.runtime_authority_id,
                        keys.database_generation, outbox.nonce, outbox.runtime_generation,
                        outbox.profile_digest, outbox.ciphertext, outbox.plaintext_len,
                        outbox.plaintext_digest, outbox.settlement_digest,
                        outbox.application_idempotency_key, admission.principal_id,
                        admission.conversation_id, admission.taskrun_id,
                        admission.execution_attempt_id, admission.fencing_token
                 FROM provider_terminal_outbox outbox
                 JOIN provider_journal_key_refs keys
                   ON keys.key_id = outbox.key_id AND keys.key_version = outbox.key_version
                 JOIN provider_execution_admissions admission
                   ON admission.dispatch_attempt_id = outbox.dispatch_attempt_id
                 WHERE outbox.state = 1
                 ORDER BY outbox.created_at, outbox.outbox_id",
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        statement
            .query_map([], |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes(row.get(6)?)?,
                    positive_u64(row.get(7)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted_output = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(8)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderTerminalOutboxRecord {
                    outbox_id: fixed_bytes(row.get(0)?)?,
                    attempt_id: DispatchAttemptId::from_bytes(fixed_bytes(row.get(1)?)?),
                    fencing_token: positive_u64(row.get(20)?)?,
                    principal_id: row.get(16)?,
                    conversation_id: ConversationId::from_bytes(fixed_bytes(row.get(17)?)?),
                    taskrun_id: TaskRunId::from_bytes(fixed_bytes(row.get(18)?)?),
                    execution_attempt_id: AttemptId::from_bytes(fixed_bytes(row.get(19)?)?),
                    terminal_sequence: nonnegative_u64(row.get(2)?)?,
                    call_digest_version: decode_call_digest_version(row.get(3)?)?,
                    key,
                    encrypted_output,
                    runtime_generation: positive_u64(row.get(9)?)?,
                    profile_digest: fixed_bytes(row.get(10)?)?,
                    settlement_digest: fixed_bytes(row.get(14)?)?,
                    application_idempotency_key: row.get(15)?,
                })
            })
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| ProviderExecutionError::JournalCorrupt)
    }

    fn acknowledge_terminal_outbox(
        &self,
        outbox_id: [u8; 16],
        receipt_digest: [u8; 32],
    ) -> Result<(), ProviderExecutionError> {
        if outbox_id == [0; 16] || receipt_digest == [0; 32] {
            return Err(ProviderExecutionError::OutboxConflict);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let existing = transaction
            .query_row(
                "SELECT dispatch_attempt_id, settlement_digest, state, receipt_digest
                 FROM provider_terminal_outbox WHERE outbox_id = ?1",
                [outbox_id.as_slice()],
                |row| {
                    Ok((
                        fixed_bytes::<16>(row.get(0)?)?,
                        fixed_bytes::<32>(row.get(1)?)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<Vec<u8>>>(3)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?
            .ok_or(ProviderExecutionError::OutboxConflict)?;
        if existing.2 == 2 {
            return if existing
                .3
                .as_deref()
                .and_then(|bytes| bytes.try_into().ok())
                == Some(receipt_digest)
            {
                Ok(())
            } else {
                Err(ProviderExecutionError::OutboxConflict)
            };
        }
        if existing.2 != 1 || existing.3.is_some() {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        let now = unix_timestamp();
        let updated_outbox = transaction
            .execute(
                "UPDATE provider_terminal_outbox
                 SET state = 2, receipt_digest = ?2, applied_at = ?3
                 WHERE outbox_id = ?1 AND state = 1 AND receipt_digest IS NULL",
                params![outbox_id.as_slice(), receipt_digest.as_slice(), now],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let updated_attempt = transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 5
                 WHERE attempt_id = ?1 AND state = 4 AND settlement_digest = ?2",
                params![existing.0.as_slice(), existing.1.as_slice()],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if updated_outbox != 1 || updated_attempt != 1 {
            return Err(ProviderExecutionError::OutboxConflict);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

    fn mark_execution_uncertain(
        &self,
        attempt_id: DispatchAttemptId,
        fencing_token: u64,
    ) -> Result<(), ProviderExecutionError> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, attempt_id)?;
        if attempt.fencing_token != fencing_token {
            return Err(ProviderExecutionError::StaleGeneration);
        }
        verify_current_runtime_lease(&transaction, &attempt)?;
        let current = attempt.state;
        if current == 6 {
            return Ok(());
        }
        if !matches!(current, 1 | 3) {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let changed = transaction
            .execute(
                "UPDATE provider_dispatch_attempts SET state = 6
                 WHERE attempt_id = ?1 AND fencing_token = ?2 AND state IN (1, 3)",
                params![
                    attempt_id.as_bytes().as_slice(),
                    execution_i64(fencing_token)?,
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::StaleGeneration);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }
}

impl ProviderTerminalPersistence for SqliteProviderExecutionStore {
    fn commit_terminal(
        &self,
        request: &ProviderTerminalCommitRequest,
    ) -> Result<ProviderTerminalCommitOutcome, ProviderExecutionError> {
        validate_terminal_commit(request)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let attempt = load_execution_attempt(&transaction, request.attempt_id())?;
        verify_attempt_for_progress(
            &attempt,
            request.fencing_token(),
            request.runtime_generation(),
            *request.profile_digest(),
        )?;
        verify_current_runtime_lease(&transaction, &attempt)?;
        if terminal_commit_exists(&transaction, request)? {
            return Ok(ProviderTerminalCommitOutcome::Replayed);
        }
        if attempt.state == 6 {
            return Err(ProviderExecutionError::AttemptUncertain);
        }
        if attempt.state != 3 {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        if attempt.call_digest_version != request.call_digest_version() {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        ensure_known_journal_key(&transaction, request.key(), &attempt)?;
        verify_terminal_journal_record(&transaction, request)?;
        let reservations = load_reservations(&transaction, &attempt.provider_idempotency_key)?;
        let usage = request.usage();
        let usage_total = usage.total_tokens();
        if usage_total > reservations.token_amount
            || request.charge_micros() > reservations.cost_amount
            || request.currency() != attempt.currency
        {
            return Err(ProviderExecutionError::ReservationMismatch);
        }
        let now = unix_timestamp();
        transaction
            .execute(
                "INSERT INTO provider_accounting_settlements (
                    dispatch_attempt_id, pricing_revision_digest, input_tokens, output_tokens,
                    cached_input_tokens, reasoning_output_tokens, charge_micros, currency,
                    settlement_digest, committed_at
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    request.attempt_id().as_bytes().as_slice(),
                    attempt.pricing_revision_digest.as_slice(),
                    execution_i64(usage.input_tokens())?,
                    execution_i64(usage.output_tokens())?,
                    execution_i64(usage.cached_input_tokens())?,
                    execution_i64(usage.reasoning_output_tokens())?,
                    execution_i64(request.charge_micros())?,
                    request.currency(),
                    request.settlement_digest().as_slice(),
                    now,
                ],
            )
            .map_err(|_| ProviderExecutionError::TerminalConflict)?;
        let next_state =
            if request.disposition() == gocode_provider::ProviderTerminalDisposition::Completed {
                let encrypted_output = request
                    .encrypted_output()
                    .ok_or(ProviderExecutionError::TerminalConflict)?;
                insert_nonce(
                    &transaction,
                    request.key(),
                    encrypted_output.nonce(),
                    2,
                    request.attempt_id(),
                    None,
                )?;
                transaction
                    .execute(
                        "INSERT INTO provider_terminal_outbox (
                            outbox_id, dispatch_attempt_id, terminal_sequence, call_digest_version,
                            key_id, key_version, nonce, runtime_generation, profile_digest,
                            ciphertext, plaintext_len, plaintext_digest, settlement_digest,
                            application_idempotency_key, state, receipt_digest, created_at,
                            applied_at
                         ) VALUES (
                            ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                            1, NULL, ?15, NULL
                         )",
                        params![
                            request.outbox_id().as_slice(),
                            request.attempt_id().as_bytes().as_slice(),
                            execution_i64(request.terminal_sequence())?,
                            encode_call_digest_version(request.call_digest_version()),
                            request.key().key_id().as_slice(),
                            execution_i64(request.key().key_version())?,
                            encrypted_output.nonce().as_slice(),
                            execution_i64(request.runtime_generation())?,
                            request.profile_digest().as_slice(),
                            encrypted_output.ciphertext(),
                            execution_i64(encrypted_output.plaintext_len())?,
                            encrypted_output.plaintext_digest().as_slice(),
                            request.settlement_digest().as_slice(),
                            request.application_idempotency_key(),
                            now,
                        ],
                    )
                    .map_err(|_| ProviderExecutionError::TerminalConflict)?;
                4_i64
            } else {
                5_i64
            };
        release_reservations(
            &transaction,
            &attempt.provider_idempotency_key,
            usage_total,
            request.charge_micros(),
            reservations,
            now,
        )?;
        let changed = transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = ?3, settlement_digest = ?4
                 WHERE attempt_id = ?1 AND fencing_token = ?2 AND state = 3",
                params![
                    request.attempt_id().as_bytes().as_slice(),
                    execution_i64(request.fencing_token())?,
                    next_state,
                    request.settlement_digest().as_slice(),
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::StaleGeneration);
        }
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        Ok(ProviderTerminalCommitOutcome::Committed)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JournalKeyState {
    Active,
    Retired,
}

struct StoredJournalKey {
    binding: ProviderJournalKeyBinding,
}

fn load_journal_key_state(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
) -> Result<Option<JournalKeyState>, ProviderExecutionError> {
    connection
        .query_row(
            "SELECT runtime_authority_id, database_generation, state
             FROM provider_journal_key_refs
             WHERE key_id = ?1 AND key_version = ?2",
            params![key.key_id().as_slice(), execution_i64(key.key_version())?,],
            |row| {
                let authority: [u8; 16] = fixed_bytes(row.get(0)?)?;
                let generation = positive_u64(row.get(1)?)?;
                if authority != key.runtime_authority_id()
                    || generation != key.database_generation()
                {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                match row.get::<_, i64>(2)? {
                    1 => Ok(JournalKeyState::Active),
                    2 => Ok(JournalKeyState::Retired),
                    _ => Err(rusqlite::Error::InvalidQuery),
                }
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn load_active_journal_key(
    connection: &Connection,
) -> Result<Option<StoredJournalKey>, ProviderExecutionError> {
    connection
        .query_row(
            "SELECT key_id, key_version, runtime_authority_id, database_generation
             FROM provider_journal_key_refs
             WHERE state = 1 AND active_slot = 1",
            [],
            |row| {
                let binding = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    fixed_bytes(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(StoredJournalKey { binding })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn ensure_journal_key_exists(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
) -> Result<(), ProviderExecutionError> {
    if load_journal_key_state(connection, key)?.is_none() {
        return Err(ProviderExecutionError::JournalKeyUnavailable);
    }
    Ok(())
}

struct ExecutionAttempt {
    state: i64,
    fencing_token: u64,
    generation: u64,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    currency: String,
    provider_idempotency_key: String,
    call_digest_version: ProviderCallDigestVersion,
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    requested_input_tokens: u64,
    requested_output_tokens: u64,
    max_cost_micros: u64,
}

fn load_execution_attempt(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<ExecutionAttempt, ProviderExecutionError> {
    connection
        .query_row(
            "SELECT dispatch.state, dispatch.fencing_token, admission.generation,
                    admission.profile_digest, admission.pricing_revision_digest,
                    admission.currency, admission.provider_idempotency_key,
                    prepared.call_digest_version, admission.runtime_authority_id,
                    admission.database_generation, admission.requested_input_tokens,
                    admission.requested_output_tokens, admission.max_cost_micros
             FROM provider_dispatch_attempts dispatch
             JOIN provider_execution_admissions admission
               ON admission.dispatch_attempt_id = dispatch.attempt_id
             JOIN provider_prepared_requests prepared
               ON prepared.call_id = admission.call_id
             WHERE dispatch.attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
            |row| {
                Ok(ExecutionAttempt {
                    state: row.get(0)?,
                    fencing_token: positive_u64(row.get(1)?)?,
                    generation: positive_u64(row.get(2)?)?,
                    profile_digest: fixed_bytes(row.get(3)?)?,
                    pricing_revision_digest: fixed_bytes(row.get(4)?)?,
                    currency: row.get(5)?,
                    provider_idempotency_key: row.get(6)?,
                    call_digest_version: decode_call_digest_version(row.get(7)?)?,
                    runtime_authority_id: fixed_bytes(row.get(8)?)?,
                    database_generation: positive_u64(row.get(9)?)?,
                    requested_input_tokens: nonnegative_u64(row.get(10)?)?,
                    requested_output_tokens: positive_u64(row.get(11)?)?,
                    max_cost_micros: positive_u64(row.get(12)?)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::JournalCorrupt)
}

fn verify_attempt_for_progress(
    attempt: &ExecutionAttempt,
    fencing_token: u64,
    generation: u64,
    profile_digest: [u8; 32],
) -> Result<(), ProviderExecutionError> {
    if attempt.fencing_token != fencing_token || attempt.generation != generation {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    if attempt.profile_digest != profile_digest {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(())
}

fn verify_current_runtime_lease(
    connection: &Connection,
    attempt: &ExecutionAttempt,
) -> Result<(), ProviderExecutionError> {
    let current = connection
        .query_row(
            "SELECT runtime_authority_id, database_generation,
                    expected_generation, lease_generation,
                    expected_fencing_token, lease_fencing_token,
                    profile_digest, pricing_revision_digest, active
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    positive_u64(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                    positive_u64(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes::<32>(row.get(6)?)?,
                    fixed_bytes::<32>(row.get(7)?)?,
                    decode_bool(row.get(8)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?
        .ok_or(ProviderExecutionError::StaleGeneration)?;
    if !current.8
        || current.0 != attempt.runtime_authority_id
        || current.1 != attempt.database_generation
        || current.2 != attempt.generation
        || current.3 != attempt.generation
        || current.4 != attempt.fencing_token
        || current.5 != attempt.fencing_token
        || current.6 != attempt.profile_digest
        || current.7 != attempt.pricing_revision_digest
    {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}

fn ensure_active_journal_key(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
    attempt: &ExecutionAttempt,
) -> Result<(), ProviderExecutionError> {
    if key.runtime_authority_id() != attempt.runtime_authority_id
        || key.database_generation() != attempt.database_generation
        || load_journal_key_state(connection, key)? != Some(JournalKeyState::Active)
    {
        return Err(ProviderExecutionError::JournalKeyUnavailable);
    }
    Ok(())
}

fn ensure_known_journal_key(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
    attempt: &ExecutionAttempt,
) -> Result<(), ProviderExecutionError> {
    if key.runtime_authority_id() != attempt.runtime_authority_id
        || key.database_generation() != attempt.database_generation
        || load_journal_key_state(connection, key)?.is_none()
    {
        return Err(ProviderExecutionError::JournalKeyUnavailable);
    }
    Ok(())
}

fn validate_journal_append(
    request: &ProviderJournalAppendRequest,
) -> Result<(), ProviderExecutionError> {
    if request.fencing_token == 0
        || request.runtime_generation == 0
        || !(1..=6).contains(&request.event_kind)
        || request.encrypted.ciphertext().len() > 2_097_152
        || (request.terminal && request.event_kind != 5)
        || (!request.terminal && request.event_kind == 5)
    {
        return Err(ProviderExecutionError::JournalCorrupt);
    }
    Ok(())
}

fn validate_poll_request(request: &ProviderPollRequest) -> Result<(), ProviderExecutionError> {
    if request.fencing_token == 0 || request.runtime_generation == 0 {
        return Err(ProviderExecutionError::StaleGeneration);
    }
    Ok(())
}

fn load_encrypted_event(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
    sequence: u64,
) -> Result<Option<ProviderJournalAppendRequest>, ProviderExecutionError> {
    let attempt = load_execution_attempt(connection, attempt_id)?;
    connection
        .query_row(
            "SELECT journal.key_id, journal.key_version, keys.runtime_authority_id,
                    keys.database_generation, journal.nonce, journal.call_digest_version,
                    journal.profile_digest, journal.runtime_generation, journal.event_kind,
                    journal.terminal, journal.ciphertext, journal.plaintext_len,
                    journal.plaintext_digest
             FROM provider_stream_journal journal
             JOIN provider_journal_key_refs keys
               ON keys.key_id = journal.key_id AND keys.key_version = journal.key_version
             WHERE journal.dispatch_attempt_id = ?1 AND journal.sequence = ?2",
            params![attempt_id.as_bytes().as_slice(), execution_i64(sequence)?,],
            |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    fixed_bytes(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(4)?)?,
                    row.get(10)?,
                    nonnegative_u64(row.get(11)?)?,
                    fixed_bytes(row.get(12)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(ProviderJournalAppendRequest {
                    attempt_id,
                    fencing_token: attempt.fencing_token,
                    sequence,
                    event_kind: u8::try_from(row.get::<_, i64>(8)?)
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                    terminal: decode_bool(row.get(9)?)?,
                    call_digest_version: decode_call_digest_version(row.get(5)?)?,
                    profile_digest: fixed_bytes(row.get(6)?)?,
                    runtime_generation: positive_u64(row.get(7)?)?,
                    key,
                    encrypted,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn next_journal_sequence(
    connection: &Connection,
    attempt_id: DispatchAttemptId,
) -> Result<u64, ProviderExecutionError> {
    let maximum: Option<i64> = connection
        .query_row(
            "SELECT MAX(sequence) FROM provider_stream_journal
             WHERE dispatch_attempt_id = ?1",
            [attempt_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    match maximum {
        Some(maximum) => nonnegative_u64(maximum)
            .map_err(|_| ProviderExecutionError::JournalCorrupt)?
            .checked_add(1)
            .ok_or(ProviderExecutionError::SequenceMismatch),
        None => Ok(0),
    }
}

fn insert_nonce(
    connection: &Connection,
    key: ProviderJournalKeyBinding,
    nonce: &[u8; 12],
    purpose: i64,
    attempt_id: DispatchAttemptId,
    sequence: Option<u64>,
) -> Result<(), ProviderExecutionError> {
    let exists: bool = connection
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_encryption_nonces
                WHERE key_id = ?1 AND key_version = ?2 AND nonce = ?3
             )",
            params![
                key.key_id().as_slice(),
                execution_i64(key.key_version())?,
                nonce.as_slice(),
            ],
            |row| row.get(0),
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if exists {
        return Err(ProviderExecutionError::NonceReuse);
    }
    connection
        .execute(
            "INSERT INTO provider_encryption_nonces (
                key_id, key_version, nonce, purpose, dispatch_attempt_id, sequence
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                key.key_id().as_slice(),
                execution_i64(key.key_version())?,
                nonce.as_slice(),
                purpose,
                attempt_id.as_bytes().as_slice(),
                sequence.map(execution_i64).transpose()?,
            ],
        )
        .map_err(|_| ProviderExecutionError::NonceReuse)?;
    Ok(())
}

fn validate_terminal_commit(
    request: &ProviderTerminalCommitRequest,
) -> Result<(), ProviderExecutionError> {
    let completed =
        request.disposition() == gocode_provider::ProviderTerminalDisposition::Completed;
    if request.outbox_id() == &[0; 16]
        || request.fencing_token() == 0
        || request.runtime_generation() == 0
        || request.settlement_digest() == &[0; 32]
        || request.currency().len() != 3
        || !request
            .currency()
            .bytes()
            .all(|byte| byte.is_ascii_uppercase())
        || request.application_idempotency_key().is_empty()
        || request.application_idempotency_key().len() > 256
        || request
            .application_idempotency_key()
            .bytes()
            .any(|byte| byte.is_ascii_control())
        || matches!(
            request.disposition(),
            gocode_provider::ProviderTerminalDisposition::CancelledUncertain
        )
        || (completed && request.usage_unavailable())
        || completed != request.encrypted_output().is_some()
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}

fn verify_terminal_journal_record(
    connection: &Connection,
    request: &ProviderTerminalCommitRequest,
) -> Result<(), ProviderExecutionError> {
    let terminal = connection
        .query_row(
            "SELECT key_id, key_version, profile_digest, runtime_generation, terminal,
                    call_digest_version
             FROM provider_stream_journal
            WHERE dispatch_attempt_id = ?1 AND sequence = ?2",
            params![
                request.attempt_id().as_bytes().as_slice(),
                execution_i64(request.terminal_sequence())?,
            ],
            |row| {
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    positive_u64(row.get(1)?)?,
                    fixed_bytes::<32>(row.get(2)?)?,
                    positive_u64(row.get(3)?)?,
                    decode_bool(row.get(4)?)?,
                    decode_call_digest_version(row.get(5)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    if terminal.0 != request.key().key_id()
        || terminal.1 != request.key().key_version()
        || terminal.2 != *request.profile_digest()
        || terminal.3 != request.runtime_generation()
        || !terminal.4
        || terminal.5 != request.call_digest_version()
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Reservations {
    token_amount: u64,
    cost_amount: u64,
}

fn load_reservations(
    connection: &Connection,
    idempotency_key: &str,
) -> Result<Reservations, ProviderExecutionError> {
    let mut statement = connection
        .prepare(
            "SELECT dimension, amount, state, settled_amount, released_at
             FROM provider_budget_reservations
             WHERE provider_idempotency_key = ?1
             ORDER BY dimension",
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    let rows = statement
        .query_map([idempotency_key], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                positive_u64(row.get(1)?)?,
                row.get::<_, i64>(2)?,
                row.get::<_, Option<i64>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    if rows.len() != 2
        || rows[0].0 != 1
        || rows[1].0 != 2
        || rows
            .iter()
            .any(|row| row.2 != 1 || row.3.is_some() || row.4.is_some())
    {
        return Err(ProviderExecutionError::ReservationMismatch);
    }
    Ok(Reservations {
        token_amount: rows[0].1,
        cost_amount: rows[1].1,
    })
}

fn release_reservations(
    connection: &Connection,
    idempotency_key: &str,
    settled_tokens: u64,
    settled_cost: u64,
    reservations: Reservations,
    released_at: i64,
) -> Result<(), ProviderExecutionError> {
    for (dimension, settled_amount) in [(1_i64, settled_tokens), (2_i64, settled_cost)] {
        let changed = connection
            .execute(
                "UPDATE provider_budget_reservations
                 SET state = 2, settled_amount = ?3, released_at = ?4
                 WHERE provider_idempotency_key = ?1 AND dimension = ?2
                   AND state = 1 AND settled_amount IS NULL AND released_at IS NULL",
                params![
                    idempotency_key,
                    dimension,
                    execution_i64(settled_amount)?,
                    released_at,
                ],
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if changed != 1 {
            return Err(ProviderExecutionError::ReservationMismatch);
        }
    }
    let changed = connection
        .execute(
            "UPDATE provider_runtime_authority_state SET
                token_budget_reserved = token_budget_reserved - ?1,
                token_budget_settled = token_budget_settled + ?2,
                cost_budget_reserved_micros = cost_budget_reserved_micros - ?3,
                cost_budget_settled_micros = cost_budget_settled_micros + ?4
             WHERE id = 1 AND token_budget_reserved >= ?1
               AND cost_budget_reserved_micros >= ?3
               AND token_budget_settled + ?2
                   <= token_budget_limit - (token_budget_reserved - ?1)
               AND cost_budget_settled_micros + ?4
                   <= cost_budget_limit_micros - (cost_budget_reserved_micros - ?3)",
            params![
                execution_i64(reservations.token_amount)?,
                execution_i64(settled_tokens)?,
                execution_i64(reservations.cost_amount)?,
                execution_i64(settled_cost)?,
            ],
        )
        .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
    if changed != 1 {
        return Err(ProviderExecutionError::ReservationMismatch);
    }
    Ok(())
}

fn terminal_commit_exists(
    connection: &Connection,
    request: &ProviderTerminalCommitRequest,
) -> Result<bool, ProviderExecutionError> {
    if request.disposition() != gocode_provider::ProviderTerminalDisposition::Completed {
        return terminal_non_delivery_commit_exists(connection, request);
    }
    let encrypted_output = request
        .encrypted_output()
        .ok_or(ProviderExecutionError::TerminalConflict)?;
    let existing = connection
        .query_row(
            "SELECT outbox.outbox_id, outbox.dispatch_attempt_id,
                    outbox.terminal_sequence, outbox.call_digest_version,
                    outbox.key_id, outbox.key_version, keys.runtime_authority_id,
                    keys.database_generation, outbox.nonce, outbox.runtime_generation,
                    outbox.profile_digest, outbox.ciphertext, outbox.plaintext_len,
                    outbox.plaintext_digest, outbox.settlement_digest,
                    outbox.application_idempotency_key,
                    accounting.input_tokens, accounting.output_tokens,
                    accounting.cached_input_tokens, accounting.reasoning_output_tokens,
                    accounting.charge_micros, accounting.currency,
                    accounting.pricing_revision_digest
             FROM provider_terminal_outbox outbox
             JOIN provider_journal_key_refs keys
               ON keys.key_id = outbox.key_id AND keys.key_version = outbox.key_version
             JOIN provider_accounting_settlements accounting
               ON accounting.dispatch_attempt_id = outbox.dispatch_attempt_id
            WHERE outbox.outbox_id = ?1 OR outbox.dispatch_attempt_id = ?2",
            params![
                request.outbox_id().as_slice(),
                request.attempt_id().as_bytes().as_slice(),
            ],
            |row| {
                let key = ProviderJournalKeyBinding::new(
                    fixed_bytes(row.get(4)?)?,
                    positive_u64(row.get(5)?)?,
                    fixed_bytes(row.get(6)?)?,
                    positive_u64(row.get(7)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let encrypted = ProviderEncryptedPayload::new(
                    fixed_bytes(row.get(8)?)?,
                    row.get(11)?,
                    nonnegative_u64(row.get(12)?)?,
                    fixed_bytes(row.get(13)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                let usage = gocode_provider::ProviderUsage::new(
                    nonnegative_u64(row.get(16)?)?,
                    nonnegative_u64(row.get(17)?)?,
                    nonnegative_u64(row.get(18)?)?,
                    nonnegative_u64(row.get(19)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((
                    fixed_bytes::<16>(row.get(0)?)?,
                    DispatchAttemptId::from_bytes(fixed_bytes(row.get(1)?)?),
                    nonnegative_u64(row.get(2)?)?,
                    decode_call_digest_version(row.get(3)?)?,
                    key,
                    encrypted,
                    positive_u64(row.get(9)?)?,
                    fixed_bytes::<32>(row.get(10)?)?,
                    fixed_bytes::<32>(row.get(14)?)?,
                    row.get::<_, String>(15)?,
                    usage,
                    nonnegative_u64(row.get(20)?)?,
                    row.get::<_, String>(21)?,
                    fixed_bytes::<32>(row.get(22)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(existing) = existing else {
        return Ok(false);
    };
    let attempt = load_execution_attempt(connection, request.attempt_id())?;
    if existing.0 != *request.outbox_id()
        || existing.1 != request.attempt_id()
        || existing.2 != request.terminal_sequence()
        || existing.3 != request.call_digest_version()
        || existing.4 != request.key()
        || existing.5.plaintext_len() != encrypted_output.plaintext_len()
        || existing.5.plaintext_digest() != encrypted_output.plaintext_digest()
        || existing.6 != request.runtime_generation()
        || existing.7 != *request.profile_digest()
        || existing.8 != *request.settlement_digest()
        || existing.9 != request.application_idempotency_key()
        || existing.10 != request.usage()
        || existing.11 != request.charge_micros()
        || existing.12 != request.currency()
        || existing.13 != attempt.pricing_revision_digest
        || !matches!(attempt.state, 4 | 5)
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(true)
}

fn terminal_non_delivery_commit_exists(
    connection: &Connection,
    request: &ProviderTerminalCommitRequest,
) -> Result<bool, ProviderExecutionError> {
    let existing = connection
        .query_row(
            "SELECT dispatch.state, dispatch.settlement_digest,
                    accounting.input_tokens, accounting.output_tokens,
                    accounting.cached_input_tokens, accounting.reasoning_output_tokens,
                    accounting.charge_micros, accounting.currency,
                    accounting.pricing_revision_digest,
                    EXISTS(
                        SELECT 1 FROM provider_terminal_outbox outbox
                        WHERE outbox.dispatch_attempt_id = dispatch.attempt_id
                    )
             FROM provider_dispatch_attempts dispatch
             JOIN provider_accounting_settlements accounting
               ON accounting.dispatch_attempt_id = dispatch.attempt_id
             WHERE dispatch.attempt_id = ?1",
            [request.attempt_id().as_bytes().as_slice()],
            |row| {
                let usage = gocode_provider::ProviderUsage::new(
                    nonnegative_u64(row.get(2)?)?,
                    nonnegative_u64(row.get(3)?)?,
                    nonnegative_u64(row.get(4)?)?,
                    nonnegative_u64(row.get(5)?)?,
                )
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok((
                    row.get::<_, i64>(0)?,
                    fixed_bytes::<32>(row.get(1)?)?,
                    usage,
                    nonnegative_u64(row.get(6)?)?,
                    row.get::<_, String>(7)?,
                    fixed_bytes::<32>(row.get(8)?)?,
                    decode_bool(row.get(9)?)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderExecutionError::JournalCorrupt)?;
    let Some(existing) = existing else {
        return Ok(false);
    };
    let attempt = load_execution_attempt(connection, request.attempt_id())?;
    if existing.0 != 5
        || existing.1 != *request.settlement_digest()
        || existing.2 != request.usage()
        || existing.3 != request.charge_micros()
        || existing.4 != request.currency()
        || existing.5 != attempt.pricing_revision_digest
        || existing.6
    {
        return Err(ProviderExecutionError::TerminalConflict);
    }
    Ok(true)
}

fn execution_i64(value: u64) -> Result<i64, ProviderExecutionError> {
    i64::try_from(value).map_err(|_| ProviderExecutionError::JournalCorrupt)
}

fn encode_call_digest_version(version: ProviderCallDigestVersion) -> i64 {
    match version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }
}

fn decode_call_digest_version(value: i64) -> rusqlite::Result<ProviderCallDigestVersion> {
    match value {
        1 => Ok(ProviderCallDigestVersion::V1),
        2 => Ok(ProviderCallDigestVersion::V2),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

#[derive(Debug)]
struct RuntimeAuthorityState {
    runtime_authority_id: [u8; 16],
    database_generation: u64,
    principal_id: String,
    owner_id: String,
    scope: String,
    expected_generation: u64,
    lease_generation: u64,
    expected_fencing_token: u64,
    lease_fencing_token: u64,
    capability_grant_id: String,
    capability_revision: u64,
    capability_allowed: bool,
    approval_id: String,
    approval_revision: u64,
    approval_allowed: bool,
    approval_expires_at: i64,
    profile_digest: [u8; 32],
    pricing_revision_digest: [u8; 32],
    token_budget_limit: u64,
    token_budget_reserved: u64,
    token_budget_settled: u64,
    cost_budget_limit_micros: u64,
    cost_budget_reserved_micros: u64,
    cost_budget_settled_micros: u64,
    authority_ttl_seconds: u64,
    state_revision: u64,
    active: bool,
}

impl RuntimeAuthorityState {
    fn matches_config(&self, config: &ProviderRuntimeAuthorityConfig) -> bool {
        self.runtime_authority_id == config.runtime_authority_id
            && self.database_generation == config.database_generation
            && self.principal_id == config.principal_id
            && self.owner_id == config.owner_id
            && self.scope == config.scope
            && self.expected_generation == config.generation
            && self.lease_generation == config.generation
            && self.expected_fencing_token == config.fencing_token
            && self.lease_fencing_token == config.fencing_token
            && self.capability_grant_id == config.capability_grant_id
            && self.capability_revision == config.capability_revision
            && self.capability_allowed == config.capability_allowed
            && self.approval_id == config.approval_id
            && self.approval_revision == config.approval_revision
            && self.approval_allowed == config.approval_allowed
            && self.approval_expires_at == config.approval_expires_at
            && self.profile_digest == config.profile_digest
            && self.pricing_revision_digest == config.pricing_revision_digest
            && self.token_budget_limit == config.token_budget_limit
            && self.cost_budget_limit_micros == config.cost_budget_limit_micros
            && self.authority_ttl_seconds == config.authority_ttl_seconds
            && self.active
    }
}

fn install_runtime_authority_in_transaction(
    transaction: &Transaction<'_>,
    config: &ProviderRuntimeAuthorityConfig,
) -> Result<(), ProviderAdmissionError> {
    match load_runtime_authority(transaction)? {
        None => insert_runtime_authority(transaction, config, 1),
        Some(existing) if existing.matches_config(config) => Ok(()),
        Some(existing) => {
            if existing.runtime_authority_id != config.runtime_authority_id
                || existing.database_generation != config.database_generation
                || config.token_budget_limit
                    < existing.token_budget_settled + existing.token_budget_reserved
                || config.cost_budget_limit_micros
                    < existing.cost_budget_settled_micros + existing.cost_budget_reserved_micros
                || config.generation < existing.expected_generation
                || (config.generation == existing.expected_generation
                    && config.fencing_token != existing.expected_fencing_token)
            {
                return Err(ProviderAdmissionError::AuthorityConflict);
            }
            replace_runtime_authority(transaction, config, existing.state_revision + 1)
        }
    }
}

fn advance_worker_lease_in_transaction(
    transaction: &Transaction<'_>,
    generation: u64,
    fencing_token: u64,
) -> Result<(), ProviderAdmissionError> {
    let generation_i64 = as_i64(generation)?;
    let fencing_token_i64 = as_i64(fencing_token)?;
    let existing =
        load_runtime_authority(transaction)?.ok_or(ProviderAdmissionError::StaleFencingToken)?;
    let changed = transaction
        .execute(
            "UPDATE provider_runtime_authority_state
             SET lease_generation = ?1, lease_fencing_token = ?2
             WHERE id = 1 AND active = 1 AND (
                    ?1 > lease_generation OR
                    (?1 = lease_generation AND ?2 = lease_fencing_token)
               )",
            params![generation_i64, fencing_token_i64],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    if existing.lease_generation != generation || existing.lease_fencing_token != fencing_token {
        transaction
            .execute(
                "UPDATE provider_dispatch_attempts
                 SET state = 6
                 WHERE state IN (1, 3) AND EXISTS (
                    SELECT 1 FROM provider_execution_admissions admission
                    WHERE admission.dispatch_attempt_id = provider_dispatch_attempts.attempt_id
                      AND (
                        admission.generation != ?1 OR
                        admission.fencing_token != ?2
                      )
                 )",
                params![generation_i64, fencing_token_i64],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    }
    Ok(())
}

fn load_runtime_authority(
    transaction: &Transaction<'_>,
) -> Result<Option<RuntimeAuthorityState>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT runtime_authority_id, database_generation, principal_id, owner_id, scope,
                    expected_generation, lease_generation, expected_fencing_token,
                    lease_fencing_token, capability_grant_id, capability_revision,
                    capability_allowed, approval_id, approval_revision, approval_allowed,
                    approval_expires_at, profile_digest, pricing_revision_digest,
                    token_budget_limit, token_budget_reserved, token_budget_settled,
                    cost_budget_limit_micros, cost_budget_reserved_micros,
                    cost_budget_settled_micros, authority_ttl_seconds, state_revision, active
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| {
                Ok(RuntimeAuthorityState {
                    runtime_authority_id: fixed_bytes(row.get(0)?)?,
                    database_generation: positive_u64(row.get(1)?)?,
                    principal_id: row.get(2)?,
                    owner_id: row.get(3)?,
                    scope: row.get(4)?,
                    expected_generation: positive_u64(row.get(5)?)?,
                    lease_generation: positive_u64(row.get(6)?)?,
                    expected_fencing_token: positive_u64(row.get(7)?)?,
                    lease_fencing_token: positive_u64(row.get(8)?)?,
                    capability_grant_id: row.get(9)?,
                    capability_revision: positive_u64(row.get(10)?)?,
                    capability_allowed: decode_bool(row.get(11)?)?,
                    approval_id: row.get(12)?,
                    approval_revision: positive_u64(row.get(13)?)?,
                    approval_allowed: decode_bool(row.get(14)?)?,
                    approval_expires_at: row.get(15)?,
                    profile_digest: fixed_bytes(row.get(16)?)?,
                    pricing_revision_digest: fixed_bytes(row.get(17)?)?,
                    token_budget_limit: nonnegative_u64(row.get(18)?)?,
                    token_budget_reserved: nonnegative_u64(row.get(19)?)?,
                    token_budget_settled: nonnegative_u64(row.get(20)?)?,
                    cost_budget_limit_micros: nonnegative_u64(row.get(21)?)?,
                    cost_budget_reserved_micros: nonnegative_u64(row.get(22)?)?,
                    cost_budget_settled_micros: nonnegative_u64(row.get(23)?)?,
                    authority_ttl_seconds: positive_u64(row.get(24)?)?,
                    state_revision: positive_u64(row.get(25)?)?,
                    active: decode_bool(row.get(26)?)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

fn insert_runtime_authority(
    transaction: &Transaction<'_>,
    config: &ProviderRuntimeAuthorityConfig,
    state_revision: u64,
) -> Result<(), ProviderAdmissionError> {
    transaction
        .execute(
            "INSERT INTO provider_runtime_authority_state (
                id, runtime_authority_id, database_generation, principal_id, owner_id, scope,
                expected_generation, lease_generation, expected_fencing_token,
                lease_fencing_token, capability_grant_id, capability_revision,
                capability_allowed, approval_id, approval_revision, approval_allowed,
                approval_expires_at, profile_digest, pricing_revision_digest,
                token_budget_limit, token_budget_reserved, token_budget_settled,
                cost_budget_limit_micros, cost_budget_reserved_micros,
                cost_budget_settled_micros, authority_ttl_seconds, state_revision, active
             ) VALUES (
                1, ?1, ?2, ?3, ?4, ?5, ?6, ?6, ?7, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16, ?17, 0, 0, ?18, 0, 0, ?19, ?20, 1
             )",
            params![
                config.runtime_authority_id.as_slice(),
                as_i64(config.database_generation)?,
                config.principal_id,
                config.owner_id,
                config.scope,
                as_i64(config.generation)?,
                as_i64(config.fencing_token)?,
                config.capability_grant_id,
                as_i64(config.capability_revision)?,
                i64::from(config.capability_allowed),
                config.approval_id,
                as_i64(config.approval_revision)?,
                i64::from(config.approval_allowed),
                config.approval_expires_at,
                config.profile_digest.as_slice(),
                config.pricing_revision_digest.as_slice(),
                as_i64(config.token_budget_limit)?,
                as_i64(config.cost_budget_limit_micros)?,
                as_i64(config.authority_ttl_seconds)?,
                as_i64(state_revision)?,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    Ok(())
}

fn replace_runtime_authority(
    transaction: &Transaction<'_>,
    config: &ProviderRuntimeAuthorityConfig,
    state_revision: u64,
) -> Result<(), ProviderAdmissionError> {
    let changed = transaction
        .execute(
            "UPDATE provider_runtime_authority_state SET
                principal_id = ?1, owner_id = ?2, scope = ?3,
                expected_generation = ?4,
                expected_fencing_token = ?5,
                capability_grant_id = ?6, capability_revision = ?7,
                capability_allowed = ?8, approval_id = ?9, approval_revision = ?10,
                approval_allowed = ?11, approval_expires_at = ?12,
                profile_digest = ?13, pricing_revision_digest = ?14,
                token_budget_limit = ?15, cost_budget_limit_micros = ?16,
                authority_ttl_seconds = ?17, state_revision = ?18, active = 1
             WHERE id = 1 AND runtime_authority_id = ?19 AND database_generation = ?20
               AND token_budget_reserved + token_budget_settled <= ?15
               AND cost_budget_reserved_micros + cost_budget_settled_micros <= ?16",
            params![
                config.principal_id,
                config.owner_id,
                config.scope,
                as_i64(config.generation)?,
                as_i64(config.fencing_token)?,
                config.capability_grant_id,
                as_i64(config.capability_revision)?,
                i64::from(config.capability_allowed),
                config.approval_id,
                as_i64(config.approval_revision)?,
                i64::from(config.approval_allowed),
                config.approval_expires_at,
                config.profile_digest.as_slice(),
                config.pricing_revision_digest.as_slice(),
                as_i64(config.token_budget_limit)?,
                as_i64(config.cost_budget_limit_micros)?,
                as_i64(config.authority_ttl_seconds)?,
                as_i64(state_revision)?,
                config.runtime_authority_id.as_slice(),
                as_i64(config.database_generation)?,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if changed != 1 {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

fn verify_runtime_authority(
    state: &RuntimeAuthorityState,
    request: &ProviderAuthorityIssueRequest,
) -> Result<(), ProviderAdmissionError> {
    if !state.active || state.principal_id != request.principal_id {
        return Err(ProviderAdmissionError::AuthorityDenied);
    }
    if state.expected_generation != state.lease_generation
        || state.expected_fencing_token != state.lease_fencing_token
    {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }
    if !state.capability_allowed {
        return Err(ProviderAdmissionError::CapabilityDenied);
    }
    if !state.approval_allowed {
        return Err(ProviderAdmissionError::ApprovalDenied);
    }
    if state.approval_expires_at <= unix_timestamp() {
        return Err(ProviderAdmissionError::ApprovalExpired);
    }
    if state.profile_digest != request.prepared.profile_digest {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    if state.pricing_revision_digest != request.pricing_revision_digest {
        return Err(ProviderAdmissionError::PricingRevisionMismatch);
    }
    Ok(())
}

fn verify_prepared(
    transaction: &Transaction<'_>,
    request: &ProviderAuthorityIssueRequest,
) -> Result<(), ProviderAdmissionError> {
    let stored = transaction
        .query_row(
            "SELECT prepared_digest, render_digest, profile_digest, call_digest_version
             FROM provider_prepared_requests WHERE call_id = ?1",
            [request.prepared.call_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    fixed_bytes::<32>(row.get(0)?)?,
                    fixed_bytes::<32>(row.get(1)?)?,
                    fixed_bytes::<32>(row.get(2)?)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        .ok_or(ProviderAdmissionError::RenderDigestMismatch)?;
    let digest_version = match request.prepared.call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    };
    if stored.0 != request.prepared.prepared_digest
        || stored.1 != request.prepared.render_digest
        || stored.2 != request.prepared.profile_digest
        || stored.3 != digest_version
    {
        return Err(ProviderAdmissionError::RenderDigestMismatch);
    }
    Ok(())
}

fn ensure_call_is_unclaimed(
    transaction: &Transaction<'_>,
    call_id: gocode_provider::ProviderCallId,
) -> Result<(), ProviderAdmissionError> {
    let exists: bool = transaction
        .query_row(
            "SELECT EXISTS(
                SELECT 1 FROM provider_dispatch_attempts WHERE call_id = ?1
             )",
            [call_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if exists {
        return Err(ProviderAdmissionError::AuthorityConflict);
    }
    Ok(())
}

struct ExistingAdmission {
    semantic_digest: [u8; 32],
    state: ProviderRepositoryState,
}

fn load_existing_admission(
    transaction: &Transaction<'_>,
    idempotency_key: &str,
) -> Result<Option<ExistingAdmission>, ProviderAdmissionError> {
    transaction
        .query_row(
            "SELECT admission.semantic_digest, dispatch.state
             FROM provider_execution_admissions admission
             JOIN provider_dispatch_attempts dispatch
               ON dispatch.attempt_id = admission.dispatch_attempt_id
             WHERE admission.provider_idempotency_key = ?1",
            [idempotency_key],
            |row| {
                Ok(ExistingAdmission {
                    semantic_digest: fixed_bytes(row.get(0)?)?,
                    state: decode_repository_state(row.get(1)?)?,
                })
            },
        )
        .optional()
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)
}

#[allow(clippy::too_many_arguments)]
fn commit_issuance(
    transaction: &Transaction<'_>,
    request: &ProviderAuthorityIssueRequest,
    state: &RuntimeAuthorityState,
    claim: &ProviderDispatchClaim,
    authority_ref: ProviderEffectAuthorityRef,
    semantic_digest: [u8; 32],
    requested_tokens: u64,
    issued_at: i64,
    expires_at: i64,
) -> Result<(), ProviderAdmissionError> {
    let requested_tokens_i64 = as_i64(requested_tokens)?;
    let requested_input_i64 = as_i64(request.requested_input_tokens)?;
    let requested_output_i64 = as_i64(request.requested_output_tokens)?;
    let max_cost_i64 = as_i64(request.max_cost_micros)?;
    let generation_i64 = as_i64(state.expected_generation)?;
    let fence_i64 = as_i64(state.expected_fencing_token)?;
    let database_generation_i64 = as_i64(state.database_generation)?;
    let authority_revision_i64 = as_i64(authority_ref.revision())?;
    let intent_id = format!("provider:{}", encode_hex(claim.attempt_id.as_bytes()));
    let budget_binding = format!(
        "provider:{}:{}",
        encode_hex(&claim.token_reservation_id),
        encode_hex(&claim.cost_reservation_id)
    );
    let permit_hex = encode_hex(&claim.permit_id);

    let reserved = transaction
        .execute(
            "UPDATE provider_runtime_authority_state SET
                token_budget_reserved = token_budget_reserved + ?1,
                cost_budget_reserved_micros = cost_budget_reserved_micros + ?2
             WHERE id = 1 AND active = 1
               AND expected_generation = lease_generation
               AND expected_fencing_token = lease_fencing_token
               AND token_budget_reserved + token_budget_settled + ?1 <= token_budget_limit
               AND cost_budget_reserved_micros + cost_budget_settled_micros + ?2
                   <= cost_budget_limit_micros",
            params![requested_tokens_i64, max_cost_i64],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    if reserved != 1 {
        return Err(ProviderAdmissionError::StaleFencingToken);
    }

    transaction
        .execute(
            "INSERT INTO provider_dispatch_attempts (
                attempt_id, call_id, permit_id, token_reservation_id, cost_reservation_id,
                fencing_token, provider_idempotency_key, prepared_digest, render_digest,
                profile_digest, state, stream_id, settlement_digest, pre_effect_rejection
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, NULL, NULL, NULL)",
            params![
                claim.attempt_id.as_bytes().as_slice(),
                claim.call_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                fence_i64,
                claim.provider_idempotency_key,
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityConflict)?;
    transaction
        .execute(
            "INSERT INTO provider_effect_authorities (
                authority_id, revision, attempt_id, permit_id, capability_grant_id,
                token_reservation_id, cost_reservation_id, prepared_digest, render_digest,
                profile_digest, owner_id, scope, fencing_token, expires_at, revoked, consumed,
                consumed_intent_id
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14,
                       0, 1, ?15)",
            params![
                authority_ref.authority_id().as_slice(),
                authority_revision_i64,
                claim.attempt_id.as_bytes().as_slice(),
                claim.permit_id.as_slice(),
                state.capability_grant_id,
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                claim.prepared_digest.as_slice(),
                claim.render_digest.as_slice(),
                claim.profile_digest.as_slice(),
                state.owner_id,
                state.scope,
                fence_i64,
                expires_at,
                intent_id,
            ],
        )
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    transaction
        .execute(
            "INSERT INTO provider_execution_admissions (
                provider_idempotency_key, semantic_digest, principal_id, conversation_id,
                taskrun_id, execution_attempt_id, call_id, dispatch_attempt_id, authority_id,
                authority_revision, permit_id, token_reservation_id, cost_reservation_id,
                runtime_authority_id, database_generation, generation, fencing_token,
                prepared_digest, render_digest, profile_digest, pricing_revision_digest,
                requested_input_tokens, requested_output_tokens, max_cost_micros, currency,
                issued_at, expires_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15,
                ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23, ?24, ?25, ?26, ?27
             )",
            params![
                request.provider_idempotency_key,
                semantic_digest.as_slice(),
                request.principal_id,
                request.conversation_id.as_bytes().as_slice(),
                request.taskrun_id.as_bytes().as_slice(),
                request.execution_attempt_id.as_bytes().as_slice(),
                request.prepared.call_id.as_bytes().as_slice(),
                claim.attempt_id.as_bytes().as_slice(),
                authority_ref.authority_id().as_slice(),
                authority_revision_i64,
                claim.permit_id.as_slice(),
                claim.token_reservation_id.as_slice(),
                claim.cost_reservation_id.as_slice(),
                state.runtime_authority_id.as_slice(),
                database_generation_i64,
                generation_i64,
                fence_i64,
                request.prepared.prepared_digest.as_slice(),
                request.prepared.render_digest.as_slice(),
                request.prepared.profile_digest.as_slice(),
                request.pricing_revision_digest.as_slice(),
                requested_input_i64,
                requested_output_i64,
                max_cost_i64,
                request.currency,
                issued_at,
                expires_at,
            ],
        )
        .map_err(|_| ProviderAdmissionError::AuthorityConflict)?;
    for (reservation_id, dimension, amount) in [
        (claim.token_reservation_id, 1_i64, requested_tokens_i64),
        (claim.cost_reservation_id, 2_i64, max_cost_i64),
    ] {
        transaction
            .execute(
                "INSERT INTO provider_budget_reservations (
                    reservation_id, provider_idempotency_key, dimension, amount, state,
                    settled_amount, released_at
                 ) VALUES (?1, ?2, ?3, ?4, 1, NULL, NULL)",
                params![
                    reservation_id.as_slice(),
                    request.provider_idempotency_key,
                    dimension,
                    amount,
                ],
            )
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    }
    transaction
        .execute(
            "INSERT INTO security_dispatch_intents (intent_id, status)
             VALUES (?1, 'uncertain')",
            [&intent_id],
        )
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_authorization_decisions
                 (intent_id, grant_id, allowed, reason)
                 VALUES (?1, ?2, 1, 'provider-runtime-issued')",
                params![intent_id, state.capability_grant_id],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_budget_consumptions
                 (intent_id, reservation_id, amount) VALUES (?1, ?2, ?3)",
                params![intent_id, budget_binding, requested_tokens_i64],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_audit_pre_effect (intent_id, side_effect_started)
                 VALUES (?1, 1)",
                [&intent_id],
            )
        })
        .and_then(|_| {
            transaction.execute(
                "INSERT INTO security_permit_claims (permit_id, intent_id)
                 VALUES (?1, ?2)",
                params![permit_hex, intent_id],
            )
        })
        .map_err(|_| ProviderAdmissionError::RepositoryFailure)?;
    Ok(())
}

struct IssuedIds {
    dispatch_attempt_id: [u8; 16],
    authority_id: [u8; 16],
    permit_id: [u8; 16],
    token_reservation_id: [u8; 16],
    cost_reservation_id: [u8; 16],
}

impl IssuedIds {
    fn random() -> Self {
        Self {
            dispatch_attempt_id: random_nonzero_id(),
            authority_id: random_nonzero_id(),
            permit_id: random_nonzero_id(),
            token_reservation_id: random_nonzero_id(),
            cost_reservation_id: random_nonzero_id(),
        }
    }
}

fn random_nonzero_id() -> [u8; 16] {
    loop {
        let mut id = [0_u8; 16];
        OsRng.fill_bytes(&mut id);
        if id != [0; 16] {
            return id;
        }
    }
}

fn execution_semantic_digest(request: &ProviderAuthorityIssueRequest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVIDER_EXECUTION_SEMANTIC_V1);
    hash_text(&mut hasher, &request.principal_id);
    hasher.update(request.conversation_id.as_bytes());
    hasher.update(request.taskrun_id.as_bytes());
    hasher.update(request.execution_attempt_id.as_bytes());
    hasher.update(request.prepared.call_id.as_bytes());
    hasher.update([match request.prepared.call_digest_version {
        ProviderCallDigestVersion::V1 => 1,
        ProviderCallDigestVersion::V2 => 2,
    }]);
    hasher.update(request.prepared.prepared_digest);
    hasher.update(request.prepared.render_digest);
    hasher.update(request.prepared.profile_digest);
    hasher.update(request.pricing_revision_digest);
    hasher.update(request.requested_input_tokens.to_be_bytes());
    hasher.update(request.requested_output_tokens.to_be_bytes());
    hasher.update(request.max_cost_micros.to_be_bytes());
    hash_text(&mut hasher, &request.currency);
    hash_text(&mut hasher, &request.provider_idempotency_key);
    hasher.finalize().into()
}

fn hash_text(hasher: &mut Sha256, text: &str) {
    hasher.update((text.len() as u64).to_be_bytes());
    hasher.update(text.as_bytes());
}

fn bounded_text(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn as_i64(value: u64) -> Result<i64, ProviderAdmissionError> {
    i64::try_from(value).map_err(|_| ProviderAdmissionError::InvalidSemanticContext)
}

fn positive_u64(value: i64) -> rusqlite::Result<u64> {
    let value = u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)?;
    if value == 0 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(value)
}

fn nonnegative_u64(value: i64) -> rusqlite::Result<u64> {
    u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_bool(value: i64) -> rusqlite::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn decode_repository_state(value: i64) -> rusqlite::Result<ProviderRepositoryState> {
    match value {
        1 => Ok(ProviderRepositoryState::Dispatching),
        2 => Ok(ProviderRepositoryState::RejectedBeforeEffect),
        3 => Ok(ProviderRepositoryState::Streaming),
        4 => Ok(ProviderRepositoryState::TerminalPendingCommit),
        5 => Ok(ProviderRepositoryState::Settled),
        6 => Ok(ProviderRepositoryState::Uncertain),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(i64::MAX)
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
