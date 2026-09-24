use crate::{
    BoundedCanonicalId, BoundedIdempotencyKey, ClientMutationDisposition, LocalStore,
    MutationIdentity, MutationOperation, MutationRecord, MutationTargetKind, SecurityStateError,
    security_recovery_read_types::{
        MutationRecoveryBatch, MutationRecoveryBinding, MutationRecoveryEvidence,
        MutationRecoveryLimit,
    },
};
use runne_secure_store::SecureStore;

impl LocalStore {
    /// Enumerates an anchored, bounded page of exact nonterminal v7 evidence.
    ///
    /// # Errors
    ///
    /// Returns an error when admission, anchoring, or persisted evidence is invalid.
    pub fn recover_anchored_mutations_v7(
        &mut self,
        secure: &dyn SecureStore,
        binding: MutationRecoveryBinding,
        limit: MutationRecoveryLimit,
    ) -> Result<MutationRecoveryBatch, SecurityStateError> {
        self.admitted_recovery_read(secure, |connection| {
            let identities = identities_for_binding(connection, &binding, Some(limit.0 + 1))?;
            let has_more = identities.len() > limit.0;
            let records = identities
                .into_iter()
                .take(limit.0)
                .map(|identity| recovery_evidence(connection, identity))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(MutationRecoveryBatch { records, has_more })
        })
    }

    /// Looks up exact anchored nonterminal v7 evidence by durable binding and key.
    ///
    /// # Errors
    ///
    /// Returns an error when admission, anchoring, or persisted evidence is invalid.
    pub fn lookup_anchored_mutation_recovery_v7(
        &mut self,
        secure: &dyn SecureStore,
        binding: MutationRecoveryBinding,
        idempotency_key: &str,
    ) -> Result<Option<MutationRecoveryEvidence>, SecurityStateError> {
        let key = BoundedIdempotencyKey::parse(idempotency_key.to_owned())?;
        self.admitted_recovery_read(secure, |connection| {
            identity_for_key(connection, &binding, key.as_str())?
                .map(|identity| recovery_evidence(connection, identity))
                .transpose()
        })
    }

    fn admitted_recovery_read<T>(
        &mut self,
        secure: &dyn SecureStore,
        read: impl FnOnce(&rusqlite::Connection) -> Result<T, SecurityStateError>,
    ) -> Result<T, SecurityStateError> {
        let profile = self
            .security
            .as_ref()
            .ok_or(SecurityStateError::AdmissionFailed)?
            .profile;
        let lock = secure.acquire_security_profile_lock(profile)?;
        // The same profile lock is acquired by every anchored writer before its
        // SQLite transaction. Holding it through both checks serializes recovery
        // with writes, so a writer cannot land between the query and post-check.
        self.verify_anchored_admission(secure, &lock)?;
        let result = read(&self.connection);
        self.verify_anchored_admission(secure, &lock)?;
        result
    }
}

fn identities_for_binding(
    connection: &rusqlite::Connection,
    binding: &MutationRecoveryBinding,
    limit: Option<usize>,
) -> Result<Vec<MutationIdentity>, SecurityStateError> {
    let mut sql = String::from(
        "SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND client_disposition IN ('prepared','dispatching','observing','retryable','reconciling') ORDER BY created_at,idempotency_key",
    );
    if limit.is_some() {
        sql.push_str(" LIMIT ?3");
    }
    let mut statement = connection.prepare(&sql)?;
    let rows = if let Some(limit) = limit {
        statement.query_map(
            rusqlite::params![
                binding.runtime_identity_digest.to_vec(),
                binding.principal_digest.to_vec(),
                i64::try_from(limit).map_err(|_| SecurityStateError::InvalidTransition)?,
            ],
            raw_identity,
        )?
    } else {
        statement.query_map(
            rusqlite::params![
                binding.runtime_identity_digest.to_vec(),
                binding.principal_digest.to_vec(),
            ],
            raw_identity,
        )?
    };
    rows.collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(identity_from_raw)
        .collect()
}

fn identity_for_key(
    connection: &rusqlite::Connection,
    binding: &MutationRecoveryBinding,
    key: &str,
) -> Result<Option<MutationIdentity>, SecurityStateError> {
    let mut statement = connection.prepare(
        "SELECT runtime_authority_digest,principal_digest,operation_kind,target_kind,target_id,idempotency_key,expected_version,semantic_digest FROM mutation_ledger WHERE runtime_authority_digest=?1 AND principal_digest=?2 AND idempotency_key=?3 AND client_disposition IN ('prepared','dispatching','observing','retryable','reconciling')",
    )?;
    let row = statement
        .query_map(
            rusqlite::params![
                binding.runtime_identity_digest.to_vec(),
                binding.principal_digest.to_vec(),
                key,
            ],
            raw_identity,
        )?
        .next()
        .transpose()?;
    row.map(identity_from_raw).transpose()
}

type RawIdentity = (
    Vec<u8>,
    Vec<u8>,
    String,
    String,
    Vec<u8>,
    String,
    i64,
    Vec<u8>,
);

fn raw_identity(row: &rusqlite::Row<'_>) -> rusqlite::Result<RawIdentity> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
    ))
}

fn identity_from_raw(raw: RawIdentity) -> Result<MutationIdentity, SecurityStateError> {
    let (runtime, principal, operation, target, target_id, key, version, semantic) = raw;
    MutationIdentity::new(
        runtime
            .try_into()
            .map_err(|_| SecurityStateError::IdentityConflict)?,
        principal
            .try_into()
            .map_err(|_| SecurityStateError::IdentityConflict)?,
        operation_from_name(&operation)?,
        target_from_name(&target)?,
        BoundedCanonicalId::parse(&target_id)?,
        key,
        u64::try_from(version).map_err(|_| SecurityStateError::IdentityConflict)?,
        semantic
            .try_into()
            .map_err(|_| SecurityStateError::IdentityConflict)?,
    )
}

fn recovery_evidence(
    connection: &rusqlite::Connection,
    identity: MutationIdentity,
) -> Result<MutationRecoveryEvidence, SecurityStateError> {
    let record = crate::security_record::load_record(connection, identity)?
        .ok_or(SecurityStateError::IdentityConflict)?;
    nonterminal(record)
}

fn nonterminal(record: MutationRecord) -> Result<MutationRecoveryEvidence, SecurityStateError> {
    if !matches!(
        record.client_state,
        ClientMutationDisposition::Prepared
            | ClientMutationDisposition::Dispatching
            | ClientMutationDisposition::Observing
            | ClientMutationDisposition::Retryable
            | ClientMutationDisposition::Reconciling
    ) {
        return Err(SecurityStateError::InvalidTransition);
    }
    Ok(MutationRecoveryEvidence {
        operation: record.identity.operation(),
        target: record.identity.target.clone(),
        idempotency_key: record.identity.idempotency_key().to_owned(),
        expected_version: record.identity.expected_version(),
        semantic_digest: record.identity.semantic_digest(),
        normalized_command: record
            .normalized_command
            .ok_or(SecurityStateError::InvalidTransition)?,
        disposition: record.client_state,
        resend_count: record.resend_count,
    })
}

fn operation_from_name(value: &str) -> Result<MutationOperation, SecurityStateError> {
    match value {
        "project_rename" => Ok(MutationOperation::ProjectRename),
        "project_create" => Ok(MutationOperation::ProjectCreate),
        "project_archive" => Ok(MutationOperation::ProjectArchive),
        "project_delete" => Ok(MutationOperation::ProjectDelete),
        "workspace_create" => Ok(MutationOperation::WorkspaceCreate),
        "workspace_bind_root" => Ok(MutationOperation::WorkspaceBindRoot),
        "workspace_open" => Ok(MutationOperation::WorkspaceOpen),
        "conversation_create" => Ok(MutationOperation::ConversationCreate),
        "conversation_generate_text" => Ok(MutationOperation::ConversationGenerateText),
        "task_run_submit" => Ok(MutationOperation::TaskRunSubmit),
        _ => Err(SecurityStateError::IdentityConflict),
    }
}

fn target_from_name(value: &str) -> Result<MutationTargetKind, SecurityStateError> {
    match value {
        "project" => Ok(MutationTargetKind::Project),
        "workspace" => Ok(MutationTargetKind::Workspace),
        "conversation" => Ok(MutationTargetKind::Conversation),
        _ => Err(SecurityStateError::IdentityConflict),
    }
}
