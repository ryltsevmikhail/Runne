/// Decrypted credential-free request and optional exact remote response identity.
pub struct RecoveredProviderRemoteAttempt {
    binding: ProviderRecoveryBinding,
    identity: ProviderRecoveryAttemptIdentity,
    rendered_request: Zeroizing<Vec<u8>>,
    response_id: Option<RemoteResponseId>,
    key: ProviderJournalKeyBinding,
}

impl RecoveredProviderRemoteAttempt {
    /// Exact local attempt identity.
    pub const fn binding(&self) -> ProviderRecoveryBinding {
        self.binding
    }
    /// Authenticated historical provider/profile/request metadata.
    pub const fn identity(&self) -> &ProviderRecoveryAttemptIdentity {
        &self.identity
    }
    /// Credential-free rendered request bytes, never included in Debug output.
    pub fn rendered_request(&self) -> &[u8] {
        self.rendered_request.as_slice()
    }
    /// Exact remote response identifier, if an early ID was durably committed.
    pub fn response_id(&self) -> Option<&RemoteResponseId> {
        self.response_id.as_ref()
    }
    /// Historical journal key identity used to authenticate recovery records.
    pub const fn key(&self) -> ProviderJournalKeyBinding {
        self.key
    }
}

impl std::fmt::Debug for RecoveredProviderRemoteAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RecoveredProviderRemoteAttempt")
            .field("binding", &self.binding)
            .field("profile_id", &self.identity.profile_id())
            .field("rendered_request_bytes", &self.rendered_request.len())
            .field("has_response_id", &self.response_id.is_some())
            .finish()
    }
}

impl<K, S> RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    /// Loads and authenticates the exact encrypted create parameters and saved response ID.
    pub fn load_persisted_attempt(
        &self,
        expected: ProviderRecoveryBinding,
    ) -> Result<Option<RecoveredProviderRemoteAttempt>, ProviderRecoveryError> {
        let Some((request, response)) = self
            .store
            .load_remote_identity(expected.provider_attempt_id())
            .map_err(|_| ProviderRecoveryError::Unavailable)?
        else {
            return Ok(None);
        };
        let b = &request.binding;
        if b.dispatch_attempt_id != expected.provider_attempt_id()
            || b.taskrun_id != expected.task_run_id()
            || b.taskrun_attempt_id != expected.task_attempt_id()
            || b.profile_digest != expected.profile_digest()
            || response
                .as_ref()
                .is_some_and(|saved| saved.binding != *b || saved.key != request.key)
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let identity = ProviderRecoveryAttemptIdentity::new(
            ProviderId::new(&b.provider_id).map_err(|_| ProviderRecoveryError::InvalidIdentity)?,
            ProviderId::new(&b.credential_realm)
                .map_err(|_| ProviderRecoveryError::InvalidIdentity)?,
            b.profile_id.clone(),
            b.profile_digest,
            b.semantic_digest,
            b.prepared_digest,
            b.pricing_digest,
            b.request_digest,
            b.runtime_authority_id,
            b.database_generation,
            b.runtime_generation,
            b.fencing_token,
        )?;
        let material = self
            .keyring
            .load_provider_journal_key(
                secure_ref_from_binding(request.key)
                    .map_err(|_| ProviderRecoveryError::Unavailable)?,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
        let rendered = open_payload(
            &material,
            &remote_request_aad(expected, &identity, request.key),
            &request.encrypted_request,
        )
        .map_err(|_| ProviderRecoveryError::Unavailable)?;
        if sha2::Sha256::digest(&rendered).as_slice() != identity.request_digest() {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let response_id = response
            .map(|saved| {
                let plain = open_payload(
                    &material,
                    &remote_response_id_aad(&saved.binding, saved.key),
                    &saved.encrypted_response_id,
                )
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
                RemoteResponseId::new(
                    String::from_utf8(plain).map_err(|_| ProviderRecoveryError::InvalidIdentity)?,
                )
            })
            .transpose()?;
        Ok(Some(RecoveredProviderRemoteAttempt {
            binding: expected,
            identity,
            rendered_request: Zeroizing::new(rendered),
            response_id,
            key: request.key,
        }))
    }
}

