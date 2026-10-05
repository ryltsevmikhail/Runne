use crate::{
    AnchoredMutationPermit, LocalStore, MAX_MUTATION_RECOVERY_RECORDS, MutationIdentity,
    SecurityStateError,
};
use runne_secure_store::SecureStore;

impl LocalStore {
    /// Anchors one normalized mutation or returns its unique semantic predecessor.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid identity, ambiguous semantic history,
    /// or unavailable secure storage.
    pub fn prepare_anchored_mutation_v7(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        command: crate::NormalizedMutationCommand,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        self.prepare_anchored_mutation_v7_inner(secure, identity, command, false)
    }

    /// Starts a fresh explicitly keyed `TaskRun` submit intent after every
    /// earlier submit for this Conversation has a verified accepted outcome.
    ///
    /// # Errors
    ///
    /// Returns an error if a prior submit is unresolved, the command is not a
    /// `TaskRun` submit, or the anchored identity conflicts with stored state.
    pub fn prepare_anchored_taskrun_submit_intent_v7(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        command: crate::NormalizedMutationCommand,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        if identity.operation() != crate::MutationOperation::TaskRunSubmit
            || !matches!(
                command,
                crate::NormalizedMutationCommand::SubmitTaskRun { .. }
            )
        {
            return Err(SecurityStateError::InvalidIdentity);
        }
        self.prepare_anchored_mutation_v7_inner(secure, identity, command, true)
    }

    fn prepare_anchored_mutation_v7_inner(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        command: crate::NormalizedMutationCommand,
        allow_new_submit_intent: bool,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        let bytes = zeroize::Zeroizing::new(command.encode()?);
        if !command.matches_identity(&identity) {
            return Err(SecurityStateError::IdentityConflict);
        }
        let reference = crate::security_ledger_v7::digest::command(&bytes);
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        let (record, anchor) = self.commit_anchored_security_write_with_lock(secure, |transaction, lock| {
            let exact_exists: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND idempotency_key=?3)",
                rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.idempotency_key()],
                |row| row.get(0),
            )?;
            if exact_exists {
                let record = crate::security_record::load_record(transaction, identity.clone(), lock, context.profile, context.database)?
                    .ok_or(SecurityStateError::IdentityConflict)?;
                return (record.normalized_command.as_ref() == Some(&command))
                    .then_some((record, false))
                    .ok_or(SecurityStateError::IdentityConflict);
            }
            if allow_new_submit_intent {
                let previous = transaction.prepare(
                    "SELECT idempotency_key,expected_version,semantic_digest FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND operation_kind='task_run_submit' AND target_kind='conversation' AND target_id=?3",
                )?.query_map(
                    rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.target()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?, row.get::<_, Vec<u8>>(2)?)),
                )?.collect::<Result<Vec<_>, _>>()?;
                for (key, version, semantic) in previous {
                    let prior_identity = MutationIdentity::new(
                        identity.runtime(), identity.principal(), identity.operation(),
                        identity.target_kind(), crate::BoundedCanonicalId::parse(identity.target())?,
                        key, u64::try_from(version).map_err(|_| SecurityStateError::IdentityConflict)?,
                        semantic.try_into().map_err(|_| SecurityStateError::IdentityConflict)?,
                    )?;
                    let prior = crate::security_record::load_record(transaction, prior_identity, lock, context.profile, context.database)?
                        .ok_or(SecurityStateError::IdentityConflict)?;
                    if prior.client_state != crate::ClientMutationDisposition::CanonicalOutcome
                        || !matches!(prior.canonical_outcome,
                            Some(crate::CanonicalMutationOutcome::TaskRunSubmitted { .. }))
                    {
                        return Err(SecurityStateError::InvalidTransition);
                    }
                }
            }
            if !allow_new_submit_intent {
            let keys = transaction
                .prepare(
                    "SELECT idempotency_key FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND operation_kind=?3 AND target_kind=?4 AND target_id=?5 AND expected_version=?6 AND semantic_digest=?7",
                )?
                .query_map(
                    rusqlite::params![
                        identity.runtime().to_vec(), identity.principal().to_vec(),
                        identity.operation_name(), identity.target_name(), identity.target(),
                        i64::try_from(identity.expected_version())
                            .map_err(|_| SecurityStateError::InvalidTransition)?,
                        identity.semantic_digest().to_vec(),
                    ],
                    |row| row.get::<_, String>(0),
                )?
                .collect::<Result<Vec<_>, _>>()?;
            if keys.len() > 1 {
                return Err(SecurityStateError::IdentityConflict);
            }
            if let Some(key) = keys.into_iter().next() {
                let existing = MutationIdentity::new(
                    identity.runtime(), identity.principal(), identity.operation(),
                    identity.target_kind(), crate::BoundedCanonicalId::parse(identity.target())?,
                    key, identity.expected_version(), identity.semantic_digest(),
                )?;
                let record = crate::security_record::load_record(transaction, existing, lock, context.profile, context.database)?
                    .ok_or(SecurityStateError::IdentityConflict)?;
                return (record.normalized_command.as_ref() == Some(&command))
                    .then_some((record, false))
                    .ok_or(SecurityStateError::IdentityConflict);
            }
            }
            let active: i64 = transaction.query_row(
                "SELECT COUNT(*) FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND client_disposition IN ('prepared','dispatching','observing','retryable','reconciling')",
                rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec()],
                |row| row.get(0),
            )?;
            if active >= i64::try_from(MAX_MUTATION_RECOVERY_RECORDS)
                .map_err(|_| SecurityStateError::InvalidTransition)?
            {
                return Err(SecurityStateError::InvalidTransition);
            }
            let encrypted = crate::security_mutation_payload::seal(
                lock, context.profile, context.database, &identity,
                crate::security_mutation_payload::PayloadKind::Command, &bytes,
            )?;
            transaction.execute(
                "INSERT INTO mutation_ledger (runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,normalized_command,canonical_outcome,resend_count,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,0,'prepared',NULL,?10,NULL,'prepared',0,0)",
                rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.operation_name(), identity.target_name(), identity.target(), identity.idempotency_key(), i64::try_from(identity.expected_version()).map_err(|_| SecurityStateError::InvalidTransition)?, identity.semantic_digest().to_vec(), encrypted, reference.as_bytes().to_vec()],
            )?;
            Ok((crate::security_record::prepared_record_v7(identity, command, reference), true))
        })?;
        Ok(AnchoredMutationPermit { record, anchor })
    }
}
