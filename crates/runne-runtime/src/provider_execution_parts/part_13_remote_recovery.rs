use runne_application::provider::{
    ProviderRemoteAttemptBinding, ProviderRemoteIdentityRecord, ProviderRemoteRecoveryStore,
    ProviderRemoteRequestIntent,
};
use runne_provider::{
    ProviderFuture, ProviderId, ProviderRecoveryAttemptIdentity, ProviderRecoveryBinding,
    ProviderRecoveryError, ProviderRemoteCheck, ProviderResponseIdentityCommitter,
    RemoteResponseId,
};
const REMOTE_REQUEST_AAD: &[u8] = b"GOCODE_PROVIDER_REMOTE_REQUEST_V1\0";
const REMOTE_RESPONSE_ID_AAD: &[u8] = b"GOCODE_PROVIDER_REMOTE_RESPONSE_ID_V1\0";

/// Runtime-owned encrypted persistence bridge for exact remote create identities.
pub struct RuntimeProviderRemoteIdentityCommitter<K: ?Sized, S: ?Sized> {
    keyring: Arc<K>,
    store: Arc<S>,
    random: SystemRandom,
}

impl<K: ?Sized, S: ?Sized> RuntimeProviderRemoteIdentityCommitter<K, S> {
    /// Constructs a bridge over the active retained journal-key service and store.
    pub fn new(keyring: Arc<K>, store: Arc<S>) -> Self {
        Self {
            keyring,
            store,
            random: SystemRandom::new(),
        }
    }
}

impl<K, S> ProviderResponseIdentityCommitter for RuntimeProviderRemoteIdentityCommitter<K, S>
where
    K: ProviderJournalKeyring + ?Sized,
    S: ProviderExecutionStore + ProviderRemoteRecoveryStore + ?Sized,
{
    fn persist_request<'a>(
        &'a self,
        binding: ProviderRecoveryBinding,
        identity: &'a ProviderRecoveryAttemptIdentity,
        rendered_request: &'a [u8],
    ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
        Box::pin(async move {
            if binding.profile_digest() != *identity.profile_digest()
                || sha2::Sha256::digest(rendered_request).as_slice() != identity.request_digest()
                || rendered_request.is_empty()
                || rendered_request.len() > 524_288
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let key = self
                .store
                .active_journal_key_binding()
                .map_err(|_| ProviderRecoveryError::Unavailable)?
                .ok_or(ProviderRecoveryError::Unavailable)?;
            if key.runtime_authority_id() != *identity.runtime_authority_id()
                || key.database_generation() != identity.database_generation()
            {
                return Err(ProviderRecoveryError::Unavailable);
            }
            let material = self
                .keyring
                .load_provider_journal_key(
                    secure_ref_from_binding(key).map_err(|_| ProviderRecoveryError::Unavailable)?,
                )
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
            let payload = seal_payload_with_nonce(
                &material,
                self.nonce()?,
                &remote_request_aad(binding, identity, key),
                rendered_request,
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
            self.store
                .persist_remote_request(&ProviderRemoteRequestIntent {
                    binding: app_binding(binding, identity),
                    key,
                    encrypted_request: payload,
                })
                .map_err(|_| ProviderRecoveryError::Unavailable)
        })
    }

    fn commit<'a>(
        &'a self,
        binding: ProviderRecoveryBinding,
        response_id: &'a RemoteResponseId,
    ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
        Box::pin(async move {
            let (request, saved_id) = self
                .store
                .load_remote_identity(binding.provider_attempt_id())
                .map_err(|_| ProviderRecoveryError::Unavailable)?
                .ok_or(ProviderRecoveryError::Unavailable)?;
            if request.binding.dispatch_attempt_id != binding.provider_attempt_id()
                || request.binding.taskrun_id != binding.task_run_id()
                || request.binding.taskrun_attempt_id != binding.task_attempt_id()
                || request.binding.profile_digest != binding.profile_digest()
            {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            let material = self
                .keyring
                .load_provider_journal_key(
                    secure_ref_from_binding(request.key)
                        .map_err(|_| ProviderRecoveryError::Unavailable)?,
                )
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
            if let Some(saved_id) = saved_id {
                if !saved_response_id_matches_request(&request, &saved_id) {
                    return Err(ProviderRecoveryError::InvalidIdentity);
                }
                let plaintext = open_payload(
                    &material,
                    &remote_response_id_aad(&request.binding, request.key),
                    &saved_id.encrypted_response_id,
                )
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
                return if plaintext.as_slice() == response_id.as_str().as_bytes() {
                    Ok(())
                } else {
                    Err(ProviderRecoveryError::InvalidIdentity)
                };
            }
            let payload = seal_payload_with_nonce(
                &material,
                self.nonce()?,
                &remote_response_id_aad(&request.binding, request.key),
                response_id.as_str().as_bytes(),
            )
            .map_err(|_| ProviderRecoveryError::Unavailable)?;
            self.store
                .commit_remote_response_id(&ProviderRemoteIdentityRecord {
                    binding: request.binding,
                    key: request.key,
                    encrypted_response_id: payload,
                })
                .map_err(|_| ProviderRecoveryError::Unavailable)
        })
    }

    fn persist_remote_check<'a>(
        &'a self,
        check: &'a ProviderRemoteCheck,
    ) -> ProviderFuture<'a, Result<(), ProviderRecoveryError>> {
        Box::pin(async move {
            let proof = check
                .operation_proof()
                .ok_or(ProviderRecoveryError::InvalidIdentity)?;
            if proof.binding() != check.binding() {
                return Err(ProviderRecoveryError::InvalidIdentity);
            }
            if let Some(terminal) = check.terminal() {
                self.persist_remote_terminal_artifact(check.binding(), terminal, proof)
            } else {
                let status = match check.status() {
                    status @ runne_provider::ProviderRemoteResponseStatus::Pending
                    | status @ runne_provider::ProviderRemoteResponseStatus::Unknown => {
                        status.clone()
                    }
                    _ => return Err(ProviderRecoveryError::InvalidIdentity),
                };
                self.store
                    .commit_remote_operation_observation(proof, status)
                    .map_err(|_| ProviderRecoveryError::Unavailable)
            }
        })
    }
}

fn saved_response_id_matches_request(
    request: &ProviderRemoteRequestIntent,
    response: &ProviderRemoteIdentityRecord,
) -> bool {
    response.binding == request.binding && response.key == request.key
}

impl<K: ?Sized, S: ?Sized> RuntimeProviderRemoteIdentityCommitter<K, S> {
    fn nonce(&self) -> Result<[u8; 12], ProviderRecoveryError> {
        loop {
            let mut nonce = [0_u8; 12];
            self.random
                .fill(&mut nonce)
                .map_err(|_| ProviderRecoveryError::Unavailable)?;
            if nonce != [0; 12] {
                return Ok(nonce);
            }
        }
    }
}

fn app_binding(
    binding: ProviderRecoveryBinding,
    identity: &ProviderRecoveryAttemptIdentity,
) -> ProviderRemoteAttemptBinding {
    ProviderRemoteAttemptBinding {
        taskrun_id: binding.task_run_id(),
        taskrun_attempt_id: binding.task_attempt_id(),
        dispatch_attempt_id: binding.provider_attempt_id(),
        provider_id: identity.provider_id().as_str().into(),
        credential_realm: identity.credential_realm().as_str().into(),
        profile_id: identity.profile_id().into(),
        profile_digest: *identity.profile_digest(),
        pricing_digest: *identity.pricing_digest(),
        semantic_digest: *identity.semantic_digest(),
        prepared_digest: *identity.prepared_digest(),
        request_digest: *identity.request_digest(),
        runtime_authority_id: *identity.runtime_authority_id(),
        database_generation: identity.database_generation(),
        runtime_generation: identity.runtime_generation(),
        fencing_token: identity.fencing_token(),
    }
}

fn remote_request_aad(
    binding: ProviderRecoveryBinding,
    identity: &ProviderRecoveryAttemptIdentity,
    key: ProviderJournalKeyBinding,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(REMOTE_REQUEST_AAD);
    remote_common_aad(&mut aad, binding, identity, key);
    aad.extend_from_slice(identity.semantic_digest());
    aad.extend_from_slice(identity.prepared_digest());
    aad.extend_from_slice(identity.request_digest());
    aad
}

fn remote_response_id_aad(
    binding: &ProviderRemoteAttemptBinding,
    key: ProviderJournalKeyBinding,
) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(REMOTE_RESPONSE_ID_AAD);
    aad.extend_from_slice(binding.taskrun_id.as_bytes());
    aad.extend_from_slice(binding.taskrun_attempt_id.as_bytes());
    aad.extend_from_slice(binding.dispatch_attempt_id.as_bytes());
    push_string(&mut aad, &binding.provider_id);
    push_string(&mut aad, &binding.credential_realm);
    push_string(&mut aad, &binding.profile_id);
    aad.extend_from_slice(&binding.profile_digest);
    aad.extend_from_slice(&binding.pricing_digest);
    aad.extend_from_slice(&binding.semantic_digest);
    aad.extend_from_slice(&binding.prepared_digest);
    aad.extend_from_slice(&binding.request_digest);
    aad.extend_from_slice(&binding.runtime_authority_id);
    aad.extend_from_slice(&binding.database_generation.to_be_bytes());
    aad.extend_from_slice(&binding.runtime_generation.to_be_bytes());
    aad.extend_from_slice(&binding.fencing_token.to_be_bytes());
    aad.extend_from_slice(&key.key_id());
    aad.extend_from_slice(&key.key_version().to_be_bytes());
    aad
}

fn remote_common_aad(
    aad: &mut Vec<u8>,
    binding: ProviderRecoveryBinding,
    identity: &ProviderRecoveryAttemptIdentity,
    key: ProviderJournalKeyBinding,
) {
    aad.extend_from_slice(binding.task_run_id().as_bytes());
    aad.extend_from_slice(binding.task_attempt_id().as_bytes());
    aad.extend_from_slice(binding.provider_attempt_id().as_bytes());
    push_string(aad, identity.provider_id().as_str());
    push_string(aad, identity.credential_realm().as_str());
    push_string(aad, identity.profile_id());
    aad.extend_from_slice(&binding.profile_digest());
    aad.extend_from_slice(identity.pricing_digest());
    aad.extend_from_slice(identity.runtime_authority_id());
    aad.extend_from_slice(&identity.database_generation().to_be_bytes());
    aad.extend_from_slice(&identity.runtime_generation().to_be_bytes());
    aad.extend_from_slice(&identity.fencing_token().to_be_bytes());
    aad.extend_from_slice(&key.key_id());
    aad.extend_from_slice(&key.key_version().to_be_bytes());
}

fn push_string(aad: &mut Vec<u8>, value: &str) {
    aad.extend_from_slice(&(value.len() as u32).to_be_bytes());
    aad.extend_from_slice(value.as_bytes());
}
