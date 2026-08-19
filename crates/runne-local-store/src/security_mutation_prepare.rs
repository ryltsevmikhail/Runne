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
        let bytes = command.encode()?;
        if !command.matches_identity(&identity) {
            return Err(SecurityStateError::IdentityConflict);
        }
        let reference = crate::security_ledger_v7::digest::command(&bytes);
        let (record, anchor) = self.commit_anchored_security_write(secure, |transaction| {
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
                let record = crate::security_record::load_record(transaction, existing)?
                    .ok_or(SecurityStateError::IdentityConflict)?;
                return (record.normalized_command.as_ref() == Some(&command))
                    .then_some((record, false))
                    .ok_or(SecurityStateError::IdentityConflict);
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
            transaction.execute(
                "INSERT INTO mutation_ledger (runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest,normalized_command,canonical_outcome,resend_count,client_disposition,runtime_disposition,command_ref,outcome_ref,recovery_summary,created_at,updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,NULL,0,'prepared',NULL,?10,NULL,'prepared',0,0)",
                rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.operation_name(), identity.target_name(), identity.target(), identity.idempotency_key(), i64::try_from(identity.expected_version()).map_err(|_| SecurityStateError::InvalidTransition)?, identity.semantic_digest().to_vec(), bytes, reference.as_bytes().to_vec()],
            )?;
            Ok((crate::security_record::prepared_record_v7(identity, command, reference), true))
        })?;
        Ok(AnchoredMutationPermit { record, anchor })
    }
}
