use super::*;
use runne_application::provider::{
    ProviderJournalKeyBinding, ProviderRemoteAttemptBinding, ProviderRemoteIdentityRecord,
    ProviderRemoteRequestIntent,
};
use runne_domain::id::{AttemptId, TaskRunId};
use runne_provider::{DispatchAttemptId, ProviderId};
use runne_secure_store::{ProviderJournalKeyMaterial, ProviderJournalKeyRef};

#[test]
fn remote_identity_aead_binds_full_attempt_and_request_metadata() {
    let key_ref = ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 3).unwrap();
    let material = ProviderJournalKeyMaterial::new(key_ref, [9; 32]).unwrap();
    let key = ProviderJournalKeyBinding::new([1; 16], 1, [2; 16], 3).unwrap();
    let binding = ProviderRecoveryBinding::new(
        TaskRunId::from_bytes([4; 16]),
        AttemptId::from_bytes([5; 16]),
        DispatchAttemptId::from_bytes([6; 16]),
        [7; 32],
    )
    .unwrap();
    let identity = ProviderRecoveryAttemptIdentity::new(
        ProviderId::new("openai-background").unwrap(),
        ProviderId::new("openai-background").unwrap(),
        "background-text-v1",
        [7; 32],
        [8; 32],
        [10; 32],
        [11; 32],
        [12; 32],
        [2; 16],
        3,
        13,
        14,
    )
    .unwrap();
    let plain_request = br#"{"model":"pinned","stream":true}"#;
    let request_aad = remote_request_aad(binding, &identity, key);
    let request =
        seal_payload_with_nonce(&material, [20; 12], &request_aad, plain_request).unwrap();
    assert_eq!(
        open_payload(&material, &request_aad, &request).unwrap(),
        plain_request
    );
    let changed_attempt = ProviderRecoveryBinding::new(
        binding.task_run_id(),
        binding.task_attempt_id(),
        DispatchAttemptId::from_bytes([15; 16]),
        binding.profile_digest(),
    )
    .unwrap();
    assert!(
        open_payload(
            &material,
            &remote_request_aad(changed_attempt, &identity, key),
            &request,
        )
        .is_err()
    );

    let response_binding = ProviderRemoteAttemptBinding {
        taskrun_id: binding.task_run_id(),
        taskrun_attempt_id: binding.task_attempt_id(),
        dispatch_attempt_id: binding.provider_attempt_id(),
        provider_id: "openai-background".into(),
        credential_realm: "openai-background".into(),
        profile_id: "background-text-v1".into(),
        profile_digest: [7; 32],
        pricing_digest: [11; 32],
        semantic_digest: [8; 32],
        prepared_digest: [10; 32],
        request_digest: [12; 32],
        runtime_authority_id: [2; 16],
        database_generation: 3,
        runtime_generation: 13,
        fencing_token: 14,
    };
    let response_aad = remote_response_id_aad(&response_binding, key);
    let response =
        seal_payload_with_nonce(&material, [21; 12], &response_aad, b"resp_bound_1").unwrap();
    assert_eq!(
        open_payload(&material, &response_aad, &response).unwrap(),
        b"resp_bound_1"
    );
    let mut altered = response_binding.clone();
    altered.pricing_digest[0] ^= 1;
    assert!(open_payload(&material, &remote_response_id_aad(&altered, key), &response,).is_err());

    let persisted_request = ProviderRemoteRequestIntent {
        binding: response_binding.clone(),
        key,
        encrypted_request: request,
    };
    let mismatched_binding = ProviderRemoteIdentityRecord {
        binding: altered,
        key,
        encrypted_response_id: response.clone(),
    };
    assert!(!saved_response_id_matches_request(
        &persisted_request,
        &mismatched_binding
    ));
    assert!(saved_response_id_matches_request(
        &persisted_request,
        &ProviderRemoteIdentityRecord {
            binding: response_binding.clone(),
            key,
            encrypted_response_id: response.clone(),
        },
    ));
    let other_key = ProviderJournalKeyBinding::new([99; 16], 1, [2; 16], 3).unwrap();
    let mismatched_key = ProviderRemoteIdentityRecord {
        binding: response_binding,
        key: other_key,
        encrypted_response_id: response,
    };
    assert!(!saved_response_id_matches_request(
        &persisted_request,
        &mismatched_key
    ));
}
