use super::*;
use runne_secure_store::{
    ProviderJournalKeyDeletionProof, ProviderJournalKeyRef, SecureStoreError,
};
struct Keys;
impl ProviderJournalKeyring for Keys {
    fn retains_multiple_provider_journal_keys(&self) -> bool {
        true
    }
    fn store_provider_journal_key(
        &self,
        _: &ProviderJournalKeyMaterial,
    ) -> Result<(), SecureStoreError> {
        Ok(())
    }
    fn load_provider_journal_key(
        &self,
        key: ProviderJournalKeyRef,
    ) -> Result<ProviderJournalKeyMaterial, SecureStoreError> {
        ProviderJournalKeyMaterial::new(key, [9; 32])
    }
    fn delete_provider_journal_key(
        &self,
        _: ProviderJournalKeyRef,
        _: ProviderJournalKeyDeletionProof,
    ) -> Result<(), SecureStoreError> {
        Ok(())
    }
}
#[test]
fn streamed_tool_stop_settlement_authenticates_journal_and_rejects_substitution() {
    let binding = runne_application::provider::ProviderRemoteAttemptBinding {
        taskrun_id: runne_domain::id::TaskRunId::from_bytes([1; 16]),
        taskrun_attempt_id: runne_domain::id::AttemptId::from_bytes([2; 16]),
        dispatch_attempt_id: DispatchAttemptId::from_bytes([3; 16]),
        provider_id: "deepseek".into(),
        credential_realm: "deepseek".into(),
        profile_id: "runne-deepseek-responses-tools/1".into(),
        profile_digest: [4; 32],
        pricing_digest: [5; 32],
        semantic_digest: [6; 32],
        prepared_digest: [7; 32],
        request_digest: [8; 32],
        runtime_authority_id: [10; 16],
        database_generation: 1,
        runtime_generation: 1,
        fencing_token: 1,
    };
    let usage = ProviderUsage::new(12, 4, 0, 0).unwrap();
    let context = ProviderEventJournalContext {
        attempt_id: binding.dispatch_attempt_id,
        fencing_token: 1,
        call_digest_version: runne_provider::ProviderCallDigestVersion::V2,
        profile_digest: binding.profile_digest,
        runtime_generation: 1,
    };
    let key = ProviderJournalKeyBinding::new([11; 16], 1, [10; 16], 1).unwrap();
    let material = Keys
        .load_provider_journal_key(secure_ref_from_binding(key).unwrap())
        .unwrap();
    let kinds = [
        ProviderStreamEventKind::Started,
        ProviderStreamEventKind::Usage { usage },
        ProviderStreamEventKind::ScannerCompleted {
            text: "OK".into(),
            disposition: ProviderTerminalDisposition::Completed,
            reason: ProviderFinishReason::Stop,
        },
    ];
    let journal: Vec<_> = kinds
        .into_iter()
        .enumerate()
        .map(|(i, kind)| {
            let event = ProviderStreamEvent::new(i as u64, kind).unwrap();
            let terminal = i == 2;
            let event_kind = event_kind_code(event.kind());
            let aad = event_aad(&context, key, i as u64, event_kind, terminal);
            let encrypted = seal_payload_with_nonce(
                &material,
                [(i + 1) as u8; 12],
                &aad,
                &serde_json::to_vec(&event).unwrap(),
            )
            .unwrap();
            ProviderJournalAppendRequest {
                attempt_id: binding.dispatch_attempt_id,
                fencing_token: 1,
                sequence: i as u64,
                event_kind,
                terminal,
                call_digest_version: context.call_digest_version,
                profile_digest: binding.profile_digest,
                runtime_generation: 1,
                key,
                encrypted,
            }
        })
        .collect();
    let kind = ProviderTerminalApplicationKind::ToolProposal;
    let digest = application_settlement_digest(
        kind,
        stream_settlement_digest(
            &context,
            &binding.pricing_digest,
            2,
            b"OK",
            usage,
            false,
            ProviderTerminalDisposition::Completed,
            9,
            "USD",
        ),
    );
    let candidate = runne_application::provider::ProviderRemoteTerminalSettlementDigestCandidate {
        status: ProviderRemoteTerminalDisposition::Completed,
        usage,
        charge_micros: 9,
        currency: "USD",
        settlement_digest: &digest,
    };
    assert!(
        verify_authenticated_stream_settlement(&Keys, &binding, candidate, &journal, kind).unwrap()
    );
    let mut wrong = candidate;
    wrong.charge_micros = 10;
    assert!(
        !verify_authenticated_stream_settlement(&Keys, &binding, wrong, &journal, kind).unwrap()
    );
    assert!(
        !verify_authenticated_stream_settlement(
            &Keys,
            &binding,
            candidate,
            &journal,
            ProviderTerminalApplicationKind::TextGeneration
        )
        .unwrap()
    );
    let mut changed = journal.clone();
    changed[1].profile_digest = [99; 32];
    assert!(
        verify_authenticated_stream_settlement(&Keys, &binding, candidate, &changed, kind).is_err()
    );
    assert!(
        verify_authenticated_stream_settlement(&Keys, &binding, candidate, &journal[..2], kind)
            .is_err()
    );
}
