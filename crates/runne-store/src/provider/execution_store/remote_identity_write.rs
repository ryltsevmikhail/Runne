use runne_application::provider::{
    ProviderRemoteAttemptBinding, ProviderRemoteIdentityRecord, ProviderRemoteRecoveryStore,
    ProviderRemoteRequestIntent,
};
include!("remote_identity_cancel.rs");
include!("remote_identity_load_methods.rs");

macro_rules! remote_request_params {
    ($b:expr,$key:expr,$enc:expr) => {
        rusqlite::params![
            $b.dispatch_attempt_id.as_bytes().as_slice(),
            $b.taskrun_id.as_bytes().as_slice(),
            $b.taskrun_attempt_id.as_bytes().as_slice(),
            $b.provider_id,
            $b.profile_id,
            $b.profile_digest.as_slice(),
            $b.pricing_digest.as_slice(),
            $b.credential_realm,
            $b.semantic_digest.as_slice(),
            $b.prepared_digest.as_slice(),
            $b.request_digest.as_slice(),
            $b.runtime_authority_id.as_slice(),
            $b.database_generation as i64,
            $b.runtime_generation as i64,
            $b.fencing_token as i64,
            $key.key_id().as_slice(),
            $key.key_version() as i64,
            $enc.nonce().as_slice(),
            $enc.ciphertext(),
            $enc.plaintext_len() as i64,
            $enc.plaintext_digest().as_slice()
        ]
    };
}

macro_rules! remote_response_params {
    ($b:expr,$key:expr,$enc:expr) => {
        rusqlite::params![
            $b.dispatch_attempt_id.as_bytes().as_slice(),
            $b.taskrun_id.as_bytes().as_slice(),
            $b.taskrun_attempt_id.as_bytes().as_slice(),
            $b.provider_id,
            $b.profile_id,
            $b.profile_digest.as_slice(),
            $b.pricing_digest.as_slice(),
            $b.credential_realm,
            $b.request_digest.as_slice(),
            $b.runtime_authority_id.as_slice(),
            $b.database_generation as i64,
            $b.runtime_generation as i64,
            $b.fencing_token as i64,
            $key.key_id().as_slice(),
            $key.key_version() as i64,
            $enc.nonce().as_slice(),
            $enc.ciphertext(),
            $enc.plaintext_len() as i64,
            $enc.plaintext_digest().as_slice()
        ]
    };
}

impl ProviderRemoteRecoveryStore for SqliteProviderExecutionStore {
    remote_cancel_requested_method!();

    fn find_remote_attempt(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        task_attempt: runne_domain::id::AttemptId,
    ) -> Result<Option<runne_provider::DispatchAttemptId>, ProviderExecutionError> {
        find_remote_attempt(self, taskrun, task_attempt)
    }

    fn find_remote_attempt_history(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        task_attempt: runne_domain::id::AttemptId,
    ) -> Result<Option<runne_provider::DispatchAttemptId>, ProviderExecutionError> {
        find_remote_attempt_history(self, taskrun, task_attempt)
    }

    fn load_remote_attempt_history(
        &self,
        taskrun: runne_domain::id::TaskRunId,
        task_attempt: runne_domain::id::AttemptId,
    ) -> Result<
        Option<runne_application::provider::ProviderRemoteAttemptRecord>,
        ProviderExecutionError,
    > {
        load_remote_attempt_history(self, taskrun, task_attempt)
    }

    fn load_remote_call_digest_version(
        &self,
        attempt: runne_provider::DispatchAttemptId,
    ) -> Result<runne_provider::ProviderCallDigestVersion, ProviderExecutionError> {
        load_remote_call_digest_version(self, attempt)
    }

    fn scan_remote_attempts(
        &self,
        after: Option<runne_provider::DispatchAttemptId>,
        limit: usize,
    ) -> Result<runne_application::provider::ProviderRemoteAttemptPage, ProviderExecutionError>
    {
        scan_remote_attempts(self, after, limit)
    }

    fn resolve_remote_attempt_binding(
        &self,
        claim: &ProviderDispatchClaim,
        provider_id: &runne_provider::ProviderId,
        credential_realm: &runne_provider::ProviderId,
        profile_id: &str,
    ) -> Result<ProviderRemoteAttemptBinding, ProviderExecutionError> {
        SqliteProviderExecutionStore::resolve_remote_attempt_binding(
            self,
            claim,
            provider_id,
            credential_realm,
            profile_id,
        )
    }

    fn issue_remote_operation_proof(
        &self,
        binding: &ProviderRemoteAttemptBinding,
        response_id: &runne_provider::RemoteResponseId,
        operation: runne_provider::ProviderRecoveryOperation,
    ) -> Result<runne_provider::ProviderRemoteOperationProof, ProviderExecutionError> {
        reserve_remote_operation_proof(self, binding, response_id, operation)
    }

    fn validate_remote_operation_proof(
        &self,
        proof: &runne_provider::ProviderRemoteOperationProof,
        response_id: &runne_provider::RemoteResponseId,
    ) -> Result<(), ProviderExecutionError> {
        validate_remote_operation_proof(self, proof, response_id)
    }

    fn persist_remote_request(
        &self,
        request: &ProviderRemoteRequestIntent,
    ) -> Result<(), ProviderExecutionError> {
        let binding = &request.binding;
        validate_remote_identity(binding, request.key, &request.encrypted_request, 524_288)?;
        if request.encrypted_request.plaintext_digest() != &binding.request_digest {
            return Err(ProviderExecutionError::JournalCorrupt);
        }
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        validate_current_remote_binding(&transaction, binding, request.key, (self.now)())?;
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM provider_remote_request_intents WHERE dispatch_attempt_id=?1)",
            [binding.dispatch_attempt_id.as_bytes().as_slice()], |row| row.get(0),
        ).map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if exists {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        insert_nonce(
            &transaction,
            request.key,
            request.encrypted_request.nonce(),
            2,
            binding.dispatch_attempt_id,
            None,
        )?;
        transaction
            .execute(
                "INSERT INTO provider_remote_request_intents (
                dispatch_attempt_id,taskrun_id,taskrun_attempt_id,provider_id,profile_id,
                profile_digest,pricing_revision_digest,credential_realm,semantic_digest,
                prepared_digest,request_digest,runtime_authority_id,database_generation,
                runtime_generation,fencing_token,key_id,key_version,nonce,ciphertext,
                plaintext_len,plaintext_digest,created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                       ?16,?17,?18,?19,?20,?21,unixepoch())",
                remote_request_params!(binding, request.key, request.encrypted_request),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

    fn commit_remote_response_id(
        &self,
        response: &ProviderRemoteIdentityRecord,
    ) -> Result<(), ProviderExecutionError> {
        let binding = &response.binding;
        validate_remote_identity(binding, response.key, &response.encrypted_response_id, 256)?;
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        validate_historical_response_binding(&transaction, binding, response.key, (self.now)())?;
        let request: Option<(Vec<u8>, Vec<u8>, i64)> = transaction.query_row(
            "SELECT request_digest,key_id,key_version FROM provider_remote_request_intents WHERE dispatch_attempt_id=?1",
            [binding.dispatch_attempt_id.as_bytes().as_slice()], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if request
            .as_ref()
            .is_none_or(|(digest, key_id, key_version)| {
                digest.as_slice() != binding.request_digest.as_slice()
                    || key_id.as_slice() != response.key.key_id().as_slice()
                    || *key_version != i64::try_from(response.key.key_version()).unwrap_or(-1)
            })
        {
            return Err(ProviderExecutionError::TerminalConflict);
        }
        let existing: Option<Vec<u8>> = transaction.query_row(
            "SELECT plaintext_digest FROM provider_remote_response_bindings WHERE dispatch_attempt_id=?1",
            [binding.dispatch_attempt_id.as_bytes().as_slice()], |row| row.get(0),
        ).optional().map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        if let Some(existing) = existing {
            return if existing.as_slice() == response.encrypted_response_id.plaintext_digest() {
                Ok(())
            } else {
                Err(ProviderExecutionError::TerminalConflict)
            };
        }
        insert_nonce(
            &transaction,
            response.key,
            response.encrypted_response_id.nonce(),
            2,
            binding.dispatch_attempt_id,
            None,
        )?;
        transaction
            .execute(
                "INSERT INTO provider_remote_response_bindings (
                dispatch_attempt_id,taskrun_id,taskrun_attempt_id,provider_id,profile_id,
                profile_digest,pricing_revision_digest,credential_realm,request_digest,
                runtime_authority_id,database_generation,runtime_generation,fencing_token,
                key_id,key_version,nonce,ciphertext,plaintext_len,plaintext_digest,created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,
                       ?16,?17,?18,?19,unixepoch())",
                remote_response_params!(binding, response.key, response.encrypted_response_id),
            )
            .map_err(|_| ProviderExecutionError::StoreUnavailable)?;
        transaction
            .commit()
            .map_err(|_| ProviderExecutionError::StoreUnavailable)
    }

    fn commit_remote_terminal_artifact(
        &self,
        artifact: &runne_application::provider::ProviderRemoteTerminalRecord,
    ) -> Result<(), ProviderExecutionError> {
        persist_remote_terminal_artifact(self, artifact)
    }

    fn commit_remote_terminal_artifact_with_proof(
        &self,
        artifact: &runne_application::provider::ProviderRemoteTerminalRecord,
        proof: &runne_provider::ProviderRemoteOperationProof,
    ) -> Result<(), ProviderExecutionError> {
        persist_remote_terminal_artifact_with_proof(self, artifact, proof)
    }

    fn commit_remote_operation_observation(
        &self,
        proof: &runne_provider::ProviderRemoteOperationProof,
        status: runne_provider::ProviderRemoteResponseStatus,
    ) -> Result<(), ProviderExecutionError> {
        consume_remote_operation_observation(self, proof, status)
    }

    remote_identity_load_methods!();
}
