use crate::{
    AnchoredMutationPermit, ClientMutationDisposition, LocalStore, MutationIdentity,
    MutationRecord, MutationTransitionMetadata, OptionalExtension, SecurityAnchorV1,
    SecurityStateError,
};
use gocode_secure_store::{SecureStore, StoredSecurityAnchor};
impl LocalStore {
    pub fn transition_anchored_mutation(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        next_state: ClientMutationDisposition,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        self.transition_anchored_mutation_with_metadata(
            secure,
            identity,
            next_state,
            MutationTransitionMetadata::new(None, None, None, "", 0)?,
        )
    }

    pub fn transition_anchored_mutation_with_metadata(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
        next_state: ClientMutationDisposition,
        metadata: MutationTransitionMetadata,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        if context.poisoned {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        let lock = secure.acquire_security_profile_lock(context.profile)?;
        let StoredSecurityAnchor::V1(anchor) = secure.read_security_anchor(&lock)? else {
            return Err(SecurityStateError::AnchorMismatch);
        };
        let current: Option<(String, Vec<u8>, i64, Vec<u8>, String)> = self.connection.query_row("SELECT operation_kind,target_id,expected_version,semantic_digest,client_disposition FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND idempotency_key=?3", rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.idempotency_key()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))).optional()?;
        let Some((operation, target, version, semantic, current)) = current else {
            return Err(SecurityStateError::IdentityConflict);
        };
        if operation != identity.operation_name()
            || target != identity.target()
            || version
                != i64::try_from(identity.expected_version())
                    .map_err(|_| SecurityStateError::InvalidIdentity)?
            || semantic != identity.semantic_digest()
        {
            return Err(SecurityStateError::IdentityConflict);
        }
        let current = parse_state(&current)?;
        if !current.transition_to(next_state) {
            return Err(SecurityStateError::InvalidTransition);
        }
        let generation = anchor
            .generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        let digest = transition_digest(identity.semantic_digest(), next_state);
        let seal = secure.seal_security_transaction(
            &lock,
            context.database,
            generation,
            digest,
            anchor.digest(),
        )?;
        let next = SecurityAnchorV1::new(
            context.profile,
            context.database,
            generation,
            digest,
            anchor.digest(),
            seal,
        )?;
        let transaction = self.connection.transaction()?;
        transaction.execute("UPDATE mutation_ledger SET client_disposition=?1,runtime_disposition=?2,command_ref=?3,outcome_ref=?4,recovery_summary=?5,updated_at=?6 WHERE runtime_authority_digest=?7 AND principal_digest=?8 AND idempotency_key=?9", rusqlite::params![state_name(next_state), metadata.runtime(), metadata.command().map(|value| value.to_vec()), metadata.outcome().map(|value| value.to_vec()), metadata.summary(), metadata.timestamp(), identity.runtime().to_vec(), identity.principal().to_vec(), identity.idempotency_key()])?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![
                i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
                digest.to_vec(),
                anchor.digest().to_vec(),
                next.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1", rusqlite::params![i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?, hex(&digest)])?;
        transaction.commit()?;
        if secure
            .compare_and_advance_anchor(&lock, &anchor, &next)
            .is_err()
            || secure.read_security_anchor(&lock).ok().as_ref()
                != Some(&StoredSecurityAnchor::V1(next.clone()))
        {
            self.security.as_mut().expect("anchored").poisoned = true;
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        Ok(AnchoredMutationPermit {
            record: MutationRecord {
                identity,
                client_state: next_state,
                runtime_disposition: None,
                command_ref: None,
                outcome_ref: None,
            },
            anchor: next,
        })
    }
    pub fn prepare_anchored_mutation(
        &mut self,
        secure: &dyn SecureStore,
        identity: MutationIdentity,
    ) -> Result<AnchoredMutationPermit, SecurityStateError> {
        let context = self
            .security
            .clone()
            .ok_or(SecurityStateError::AdmissionFailed)?;
        if context.poisoned {
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        let lock = secure.acquire_security_profile_lock(context.profile)?;
        let StoredSecurityAnchor::V1(anchor) = secure.read_security_anchor(&lock)? else {
            return Err(SecurityStateError::AnchorMismatch);
        };
        let duplicate: Option<(String, Vec<u8>, i64, Vec<u8>)> = self.connection.query_row("SELECT operation_kind,target_id,expected_version,semantic_digest FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND idempotency_key=?3", rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.idempotency_key()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))).optional()?;
        if let Some((operation, target, version, semantic)) = duplicate {
            if operation != identity.operation_name()
                || target != identity.target()
                || version
                    != i64::try_from(identity.expected_version())
                        .map_err(|_| SecurityStateError::InvalidIdentity)?
                || semantic != identity.semantic_digest()
            {
                return Err(SecurityStateError::IdentityConflict);
            }
            return Ok(permit(identity, anchor));
        }
        let generation = anchor
            .generation
            .checked_add(1)
            .ok_or(SecurityStateError::InvalidTransition)?;
        let digest = identity.semantic_digest();
        let seal = secure.seal_security_transaction(
            &lock,
            context.database,
            generation,
            digest,
            anchor.digest(),
        )?;
        let next = SecurityAnchorV1::new(
            context.profile,
            context.database,
            generation,
            digest,
            anchor.digest(),
            seal,
        )?;
        let transaction = self.connection.transaction()?;
        transaction.execute("INSERT INTO mutation_ledger (runtime_authority_digest, principal_digest, operation_kind, target_kind, target_id, idempotency_key, expected_version, semantic_digest, client_disposition, recovery_summary, created_at, updated_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'prepared','prepared',0,0)", rusqlite::params![identity.runtime().to_vec(), identity.principal().to_vec(), identity.operation_name(), identity.target_name(), identity.target(), identity.idempotency_key(), i64::try_from(identity.expected_version()).map_err(|_| SecurityStateError::InvalidTransition)?, digest.to_vec()])?;
        transaction.execute(
            "INSERT INTO security_transactions VALUES (?1,?2,?3,?4,1)",
            rusqlite::params![
                i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?,
                digest.to_vec(),
                anchor.digest().to_vec(),
                next.sealed_transaction.as_bytes()
            ],
        )?;
        transaction.execute("UPDATE meta SET db_generation=?1,last_transaction_digest=?2,commit_marker=1 WHERE singleton=1", rusqlite::params![i64::try_from(generation).map_err(|_| SecurityStateError::InvalidTransition)?, hex(&digest)])?;
        transaction.commit()?;
        if secure
            .compare_and_advance_anchor(&lock, &anchor, &next)
            .is_err()
            || secure.read_security_anchor(&lock).ok().as_ref()
                != Some(&StoredSecurityAnchor::V1(next.clone()))
        {
            self.security.as_mut().expect("anchored").poisoned = true;
            return Err(SecurityStateError::AnchorAdvanceFailed);
        }
        Ok(permit(identity, next))
    }
}
fn parse_state(value: &str) -> Result<ClientMutationDisposition, SecurityStateError> {
    match value {
        "prepared" => Ok(ClientMutationDisposition::Prepared),
        "dispatching" => Ok(ClientMutationDisposition::Dispatching),
        "observing" => Ok(ClientMutationDisposition::Observing),
        "retryable" => Ok(ClientMutationDisposition::Retryable),
        "reconciling" => Ok(ClientMutationDisposition::Reconciling),
        _ => Err(SecurityStateError::InvalidTransition),
    }
}
fn state_name(value: ClientMutationDisposition) -> &'static str {
    match value {
        ClientMutationDisposition::Prepared => "prepared",
        ClientMutationDisposition::Dispatching => "dispatching",
        ClientMutationDisposition::Observing => "observing",
        ClientMutationDisposition::CanonicalOutcome => "canonical_outcome",
        ClientMutationDisposition::Retryable => "retryable",
        ClientMutationDisposition::Reconciling => "reconciling",
        ClientMutationDisposition::ManualResolution => "manual_resolution",
    }
}
fn transition_digest(identity: [u8; 32], state: ClientMutationDisposition) -> [u8; 32] {
    let mut value = identity;
    value[0] ^= state_name(state).len() as u8;
    value
}
fn permit(identity: MutationIdentity, anchor: SecurityAnchorV1) -> AnchoredMutationPermit {
    AnchoredMutationPermit {
        record: MutationRecord {
            identity,
            client_state: ClientMutationDisposition::Prepared,
            runtime_disposition: None,
            command_ref: None,
            outcome_ref: None,
        },
        anchor,
    }
}
fn hex(value: &[u8; 32]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}
