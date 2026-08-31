use runne_application::provider::{
    ProviderEncryptedPayload, ProviderExecutionError, ProviderExecutionStore,
    ProviderJournalAppendOutcome, ProviderJournalAppendRequest, ProviderJournalKeyBinding,
    ProviderPollRequest, ProviderTerminalCommitOutcome,
};
use runne_provider::{ProviderCallDigestVersion, ProviderUsage};
use runne_runtime::provider_execution::{
    ProviderTerminalCommitRequest, ProviderTerminalPersistence,
};
use runne_store::provider::MarkProviderStreaming;

fn terminal_setup(
    name: &str,
    call_byte: u8,
) -> (
    ArmedProviderTestDatabase,
    ProviderDispatchClaim,
    ProviderTerminalCommitRequest,
) {
    let (database, request, _record) = setup(name, call_byte);
    let claim = issue_winner(&database, &request);
    let terminal = terminal_request_for_claim(&database, &claim, call_byte);
    (database, claim, terminal)
}

fn terminal_request_for_claim(
    database: &validated_reopen::ProviderTestDatabase,
    claim: &ProviderDispatchClaim,
    call_byte: u8,
) -> ProviderTerminalCommitRequest {
    database
        .dispatch()
        .mark_streaming(&MarkProviderStreaming {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            stream_id: runne_provider::ProviderStreamId::from_bytes(
                [call_byte.wrapping_add(40); 16],
            ),
        })
        .unwrap();
    let config = runtime_config();
    let key = ProviderJournalKeyBinding::new(
        [9; 16],
        1,
        config.runtime_authority_id,
        config.database_generation,
    )
    .unwrap();
    let execution = database.execution();
    crate::online_proof::activate(&execution, key);
    execution
        .begin_provider_poll(&ProviderPollRequest {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            cursor: 0,
            profile_digest: [2; 32],
            runtime_generation: 11,
        })
        .unwrap();
    assert_eq!(
        execution
            .append_encrypted_event(&ProviderJournalAppendRequest {
                attempt_id: claim.attempt_id,
                fencing_token: claim.fencing_token,
                sequence: 0,
                event_kind: 5,
                terminal: true,
                call_digest_version: ProviderCallDigestVersion::V2,
                profile_digest: [2; 32],
                runtime_generation: 11,
                key,
                encrypted: encrypted_payload(
                    call_byte.wrapping_add(60),
                    call_byte.wrapping_add(70)
                ),
            })
            .unwrap(),
        ProviderJournalAppendOutcome::Inserted
    );
    ProviderTerminalCommitRequest::forge_for_tests(
        [call_byte.wrapping_add(80); 16],
        claim.attempt_id,
        claim.fencing_token,
        0,
        ProviderCallDigestVersion::V2,
        key,
        encrypted_payload(call_byte.wrapping_add(90), call_byte.wrapping_add(100)),
        11,
        [2; 32],
        ProviderUsage::new(500, 900, 0, 0).unwrap(),
        40_000,
        "USD".to_owned(),
        [call_byte.wrapping_add(110); 32],
        format!("terminal-recovery-{call_byte}"),
    )
}

fn encrypted_payload(nonce_byte: u8, plaintext_byte: u8) -> ProviderEncryptedPayload {
    ProviderEncryptedPayload::new(
        [nonce_byte; 12],
        vec![plaintext_byte; 32],
        16,
        [plaintext_byte; 32],
    )
    .unwrap()
}
