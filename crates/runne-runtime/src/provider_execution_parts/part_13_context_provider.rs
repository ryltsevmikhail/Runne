use runne_provider::{
    ProviderDispatchClaim, ProviderRecoveryDispatchContext,
    ProviderRecoveryDispatchContextProvider,
};

impl<K, S> ProviderRecoveryDispatchContextProvider for RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized + 'static,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized + 'static,
{
    fn for_new_dispatch<'a>(
        &'a self,
        claim: &'a ProviderDispatchClaim,
        provider_id: &'a ProviderId,
        credential_realm: &'a ProviderId,
        profile_id: &'a str,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        Box::pin(async move {
            if self.store.load_remote_identity(claim.attempt_id)
                .map_err(|_| ProviderRecoveryError::Unavailable)?.is_some()
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let b = self.store.resolve_remote_attempt_binding(claim, provider_id, credential_realm, profile_id)
                .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
            let identity = ProviderRecoveryAttemptIdentity::new(
                provider_id.clone(), credential_realm.clone(), profile_id,
                b.profile_digest, b.semantic_digest, b.prepared_digest, b.pricing_digest,
                b.request_digest, b.runtime_authority_id, b.database_generation,
                b.runtime_generation, b.fencing_token,
            )?;
            let binding = ProviderRecoveryBinding::new(b.taskrun_id, b.taskrun_attempt_id,
                b.dispatch_attempt_id, b.profile_digest)?;
            let committer = std::sync::Arc::new(RuntimeProviderRemoteIdentityCommitter {
                keyring: std::sync::Arc::clone(&self.keyring),
                store: std::sync::Arc::clone(&self.store),
                random: SystemRandom::new(),
            });
            Ok(ProviderRecoveryDispatchContext::new_exact(binding, identity, committer))
        })
    }

    fn for_persisted_new_dispatch<'a>(
        &'a self,
        claim: &'a ProviderDispatchClaim,
        provider_id: &'a ProviderId,
        credential_realm: &'a ProviderId,
        profile_id: &'a str,
        rendered_request: &'a [u8],
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        Box::pin(async move {
            let binding = self.store.resolve_remote_attempt_binding(
                claim, provider_id, credential_realm, profile_id,
            ).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
            let attempt = ProviderRecoveryBinding::new(
                binding.taskrun_id, binding.taskrun_attempt_id,
                binding.dispatch_attempt_id, binding.profile_digest,
            )?;
            let snapshot = self.store.load_remote_attempt(claim.attempt_id)
                .map_err(|_| ProviderRecoveryError::Unavailable)?
                .ok_or(ProviderRecoveryError::InvalidIdentity)?;
            if snapshot.request.binding != binding || snapshot.response.is_some()
                || snapshot.terminal.is_some()
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let saved = self.load_persisted_attempt(attempt)?
                .ok_or(ProviderRecoveryError::Unavailable)?;
            if saved.response_id().is_some() || saved.identity().provider_id() != provider_id
                || saved.identity().credential_realm() != credential_realm
                || saved.identity().profile_id() != profile_id
                || saved.rendered_request() != rendered_request
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let committer = std::sync::Arc::new(RuntimeProviderRemoteIdentityCommitter {
                keyring: std::sync::Arc::clone(&self.keyring),
                store: std::sync::Arc::clone(&self.store),
                random: SystemRandom::new(),
            });
            Ok(ProviderRecoveryDispatchContext::new_exact(
                attempt, saved.identity().clone(), committer,
            ))
        })
    }

    fn for_dispatch<'a>(
        &'a self,
        claim: &'a ProviderDispatchClaim,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        Box::pin(async move {
            let (request, response) = self
                .store
                .load_remote_identity(claim.attempt_id)
                .map_err(|_| ProviderRecoveryError::Unavailable)?
                .ok_or(ProviderRecoveryError::InvalidIdentity)?;
            let saved = response.ok_or(ProviderRecoveryError::Unavailable)?;
            let b = &request.binding;
            if b.dispatch_attempt_id != claim.attempt_id
                || b.provider_id != claim.provider_id.as_str()
                || b.profile_digest != claim.profile_digest
                || b.prepared_digest != claim.prepared_digest
                || b.request_digest != claim.render_digest
                || saved.binding != *b
                || saved.key != request.key
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let binding = ProviderRecoveryBinding::new(
                b.taskrun_id,
                b.taskrun_attempt_id,
                b.dispatch_attempt_id,
                b.profile_digest,
            )?;
            let attempt = self
                .load_persisted_attempt(binding)?
                .ok_or(ProviderRecoveryError::Unavailable)?;
            if attempt.response_id().is_none() || attempt.identity().provider_id() != &claim.provider_id {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let committer = std::sync::Arc::new(RuntimeProviderRemoteIdentityCommitter {
                keyring: std::sync::Arc::clone(&self.keyring),
                store: std::sync::Arc::clone(&self.store),
                random: SystemRandom::new(),
            });
            Ok(ProviderRecoveryDispatchContext::new_exact(
                binding,
                attempt.identity().clone(),
                committer,
            ))
        })
    }
}
