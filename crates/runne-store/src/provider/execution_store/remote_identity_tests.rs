use runne_application::provider::{
    ProviderExecutionStore, ProviderRemoteAttemptBinding, ProviderRemoteRecoveryStore,
};
use runne_provider::{
    ModelRef, PreparedRequest, ProviderCall, ProviderCallId, ProviderId,
    ProviderRecoveryAttemptIdentity, ProviderRecoveryBinding, ProviderResponseIdentityCommitter,
    RemoteResponseId,
};
use runne_runtime::provider_execution::RuntimeProviderRemoteIdentityCommitter;
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyMaterial, ProviderJournalKeyRef,
    ProviderJournalKeyStatus, ProviderJournalKeyring, SecureStoreError,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use super::super::credential_lifecycle::online_test_support::complete_pair;
use super::authority_test_support::{Fixture, configured_connection, prepare_request_for_provider};
use super::secondary_profile_grant_tests;
use super::{ProviderAuthorityIssueOutcome, SqliteProviderExecutionStore};

struct TestJournalKeyring(ProviderJournalKeyRef);

impl ProviderJournalKeyring for TestJournalKeyring {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }
    fn store_provider_journal_key(
        &self,
        key: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        (key.key_ref() == self.0)
            .then_some(())
            .ok_or(SecureStoreError::CorruptProviderJournalKey)
    }
    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        (key == self.0)
            .then_some(())
            .ok_or(SecureStoreError::ProviderJournalKeyNotFound)?;
        ProviderJournalKeyMaterial::new(key, [9; 32])
    }
    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Err(SecureStoreError::DeletionDenied)
    }
    fn provider_journal_key_status(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyStatus, SecureStoreError> {
        Ok(if key == self.0 {
            ProviderJournalKeyStatus::Available
        } else {
            ProviderJournalKeyStatus::Missing
        })
    }
}

#[test]
fn sqlite_persists_exact_request_and_response_identity_for_effect_started_attempt() {
    let (mut fixture, lifecycle) = Fixture::new_with_online_credentials(100, |store| {
        complete_pair(store, 75, "remote-identity-online");
    });
    fixture.config.profile_digest = [22; 32];
    fixture.config.pricing_revision_digest = [33; 32];
    fixture.install();
    let grant = secondary_profile_grant_tests::grant(&fixture, "openai");
    let request = prepare_request_for_provider(fixture.launch(), &fixture.path, 75, "openai");
    let admission = match fixture
        .store
        .issue_secondary_profile(fixture.launch(), &grant, &request)
        .unwrap()
    {
        ProviderAuthorityIssueOutcome::Winner(value) => value,
        ProviderAuthorityIssueOutcome::Existing { .. } => panic!("fresh admission"),
    };
    let authorization = lifecycle
        .authorize_online_dispatch(fixture.launch(), admission.claim(), 100)
        .unwrap();
    let (_, credential_binding) = authorization.split();
    fixture
        .store
        .start_online_effect(fixture.launch(), admission.claim(), &credential_binding)
        .unwrap();

    let key = fixture.store.active_journal_key_binding().unwrap().unwrap();
    let rendered_call = ProviderCall::new(
        ProviderCallId::from_bytes([75; 16]),
        ModelRef::new(ProviderId::new("openai").unwrap(), "fixture-model", "v1").unwrap(),
        [5; 32],
        1_024,
        serde_json::Value::Null,
    )
    .unwrap();
    let rendered = PreparedRequest::from_call(&rendered_call).unwrap();
    let binding = ProviderRemoteAttemptBinding {
        taskrun_id: request.taskrun_id,
        taskrun_attempt_id: request.execution_attempt_id,
        dispatch_attempt_id: admission.claim().attempt_id,
        provider_id: "openai".into(),
        credential_realm: "openai".into(),
        profile_id: "background-text-v1".into(),
        profile_digest: [2; 32],
        pricing_digest: [3; 32],
        semantic_digest: super::execution_semantic_digest(&request),
        prepared_digest: request.prepared.prepared_digest,
        request_digest: request.prepared.render_digest,
        runtime_authority_id: [1; 16],
        database_generation: 7,
        runtime_generation: 11,
        fencing_token: 13,
    };
    assert_ne!(binding.semantic_digest, binding.request_digest);
    assert_eq!(*rendered.render_digest(), binding.request_digest);
    let recovery_binding = ProviderRecoveryBinding::new(
        binding.taskrun_id,
        binding.taskrun_attempt_id,
        binding.dispatch_attempt_id,
        binding.profile_digest,
    )
    .unwrap();
    let identity = ProviderRecoveryAttemptIdentity::new(
        ProviderId::new("openai").unwrap(),
        ProviderId::new("openai").unwrap(),
        binding.profile_id.clone(),
        binding.profile_digest,
        binding.semantic_digest,
        binding.prepared_digest,
        binding.pricing_digest,
        binding.request_digest,
        binding.runtime_authority_id,
        binding.database_generation,
        binding.runtime_generation,
        binding.fencing_token,
    )
    .unwrap();
    let key_ref = ProviderJournalKeyRef::new(
        key.key_id(),
        key.key_version(),
        key.runtime_authority_id(),
        key.database_generation(),
    )
    .unwrap();
    let keyring = Arc::new(TestJournalKeyring(key_ref));
    let store = Arc::new(fixture.store);
    let committer =
        RuntimeProviderRemoteIdentityCommitter::new(Arc::clone(&keyring), Arc::clone(&store));
    let wrong_digest_payload = runne_application::provider::ProviderEncryptedPayload::new(
        [69; 12],
        vec![0x91; rendered.rendered_bytes().len() + 16],
        rendered.rendered_bytes().len() as u64,
        [99; 32],
    )
    .unwrap();
    assert!(
        store
            .persist_remote_request(&runne_application::provider::ProviderRemoteRequestIntent {
                binding: binding.clone(),
                key,
                encrypted_request: wrong_digest_payload,
            })
            .is_err()
    );
    futures::executor::block_on(committer.persist_request(
        recovery_binding,
        &identity,
        rendered.rendered_bytes(),
    ))
    .unwrap();
    let response_id = RemoteResponseId::new("resp_sqlite_1").unwrap();
    let response_digest: [u8; 32] = Sha256::digest(response_id.as_str().as_bytes()).into();
    let other_key_id = [88; 16];
    store
        .connection
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO provider_journal_key_refs (
                key_id,key_version,runtime_authority_id,database_generation,
                state,active_slot,created_at,retired_at
             ) VALUES (?1,1,?2,?3,2,NULL,1,2)",
            rusqlite::params![
                other_key_id.as_slice(),
                key.runtime_authority_id().as_slice(),
                key.database_generation() as i64
            ],
        )
        .unwrap();
    let other_key = runne_application::provider::ProviderJournalKeyBinding::new(
        other_key_id,
        1,
        key.runtime_authority_id(),
        key.database_generation(),
    )
    .unwrap();
    assert!(
        store
            .commit_remote_response_id(&runne_application::provider::ProviderRemoteIdentityRecord {
                binding: binding.clone(),
                key: other_key,
                encrypted_response_id: runne_application::provider::ProviderEncryptedPayload::new(
                    [72; 12],
                    vec![0x71; response_id.as_str().len() + 16],
                    response_id.as_str().len() as u64,
                    response_digest,
                )
                .unwrap(),
            })
            .is_err()
    );
    let (request_after_rejection, response_after_rejection) = store
        .load_remote_identity(binding.dispatch_attempt_id)
        .unwrap()
        .unwrap();
    assert!(response_after_rejection.is_none());
    assert_eq!(request_after_rejection.binding, binding);
    let nonce_count: i64 = store
        .connection
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM provider_encryption_nonces WHERE dispatch_attempt_id=?1",
            [binding.dispatch_attempt_id.as_bytes().as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(nonce_count, 1);
    futures::executor::block_on(committer.commit(recovery_binding, &response_id)).unwrap();

    let (loaded_request, loaded_id) = store
        .load_remote_identity(binding.dispatch_attempt_id)
        .unwrap()
        .unwrap();
    assert_eq!(loaded_request.binding, binding);
    let request_digest: [u8; 32] = Sha256::digest(rendered.rendered_bytes()).into();
    assert_eq!(
        loaded_request.encrypted_request.plaintext_digest(),
        &request_digest
    );
    assert_ne!(
        loaded_request.encrypted_request.ciphertext(),
        rendered.rendered_bytes()
    );
    let loaded_id = loaded_id.unwrap();
    assert_eq!(loaded_id.binding, loaded_request.binding);
    assert_eq!(loaded_id.key, key);
    assert_ne!(request_digest, response_digest);
    assert_eq!(
        loaded_id.encrypted_response_id.plaintext_digest(),
        &response_digest
    );
    assert_ne!(
        loaded_id.encrypted_response_id.ciphertext(),
        response_id.as_str().as_bytes()
    );
    let path = fixture.path.clone();
    drop(lifecycle);
    drop(committer);
    drop(store);
    let path_text = path.to_str().unwrap();
    let reopened = Arc::new(
        SqliteProviderExecutionStore::open_with_connection(path_text, configured_connection(&path))
            .unwrap(),
    );
    let recovered_committer =
        RuntimeProviderRemoteIdentityCommitter::new(Arc::clone(&keyring), Arc::clone(&reopened));
    let recovered = recovered_committer
        .load_persisted_attempt(recovery_binding)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.rendered_request(), rendered.rendered_bytes());
    assert_eq!(
        recovered.response_id().unwrap().as_str(),
        response_id.as_str()
    );
    assert!(!format!("{recovered:?}").contains("fixture-model"));
    futures::executor::block_on(recovered_committer.commit(recovery_binding, &response_id))
        .unwrap();
    assert!(
        futures::executor::block_on(recovered_committer.commit(
            recovery_binding,
            &RemoteResponseId::new("resp_other_attempt").unwrap(),
        ))
        .is_err()
    );
}
