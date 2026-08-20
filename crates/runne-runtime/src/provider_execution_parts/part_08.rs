#[cfg(test)]
mod sourcecraft_persistence_tests {
    use super::*;

    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    #[test]
    fn sourcecraft_provider_persistence_vector_is_not_a_runne_alias() {
        // Source-pinned at sourcecraft/main 556f09eb, before the RUNNE rename.
        let key_ref = ProviderJournalKeyRef::new([1; 16], 1, [2; 16], 3).unwrap();
        let material = ProviderJournalKeyMaterial::new(key_ref, [4; 32]).unwrap();
        let key = binding_from_secure_ref(key_ref).unwrap();
        let context = ProviderEventJournalContext {
            attempt_id: DispatchAttemptId::from_bytes([5; 16]),
            fencing_token: 6,
            call_digest_version: ProviderCallDigestVersion::V2,
            profile_digest: [7; 32],
            runtime_generation: 8,
        };
        let plaintext = b"sourcecraft-provider-event";
        let digest = bytes("52d9fe5edbff56aaf0c8e0a891b5117d7829e7de8da50e02641de5e66c636e9d");
        let sourcecraft = ProviderEncryptedPayload::new(
            [9; 12],
            hex::decode("8c0825fae40848a3bc3b1869d0acddee8f1a9d49b2ff34202982edee1ec4841888be792d2302e879e02e").unwrap(),
            u64::try_from(plaintext.len()).unwrap(),
            digest,
        )
        .unwrap();
        let runne_alias = ProviderEncryptedPayload::new(
            [9; 12],
            hex::decode("8c0825fae40848a3bc3b1869d0acddee8f1a9d49b2ff3420298253fa39a13ce3df9530aec02924a0941b").unwrap(),
            u64::try_from(plaintext.len()).unwrap(),
            digest,
        )
        .unwrap();
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&context, key, 0, 2, false),
                &sourcecraft
            ),
            Ok(plaintext.to_vec())
        );
        assert_eq!(
            open_payload(
                &material,
                &event_aad(&context, key, 0, 2, false),
                &runne_alias
            ),
            Err(RuntimeProviderExecutionError::JournalCorrupt)
        );
        let outbox_id = bytes("edef782d29c79023c49ba615729a7f3c");
        assert_eq!(stable_outbox_id(&context, 9), outbox_id);
        let expected_settlement =
            bytes("62260d0dbf86b0c7fe46e52ced397fb9309e596e619b4fbe4fad70e492ca14b6");
        let pricing = ProviderTerminalPricingBinding::with_reservation(
            [3; 32],
            "USD".to_owned(),
            500,
            900,
            50_000,
        )
        .unwrap();
        assert_eq!(
            settlement_digest(
                &context,
                &pricing,
                9,
                b"sourcecraft-outbox-output",
                ProviderUsage::new(500, 900, 0, 0).unwrap(),
                false,
                ProviderTerminalDisposition::Completed,
                40_000,
                "USD",
            ),
            expected_settlement
        );
        let record = ProviderTerminalOutboxRecord {
            outbox_id,
            attempt_id: context.attempt_id,
            fencing_token: context.fencing_token,
            principal_id: "sourcecraft-principal".to_owned(),
            conversation_id: runne_domain::id::ConversationId::from_bytes([11; 16]),
            taskrun_id: runne_domain::id::TaskRunId::from_bytes([12; 16]),
            execution_attempt_id: runne_domain::id::AttemptId::from_bytes([13; 16]),
            terminal_sequence: 9,
            call_digest_version: context.call_digest_version,
            key,
            encrypted_output: sourcecraft,
            runtime_generation: context.runtime_generation,
            profile_digest: context.profile_digest,
            settlement_digest: expected_settlement,
            application_idempotency_key: "sourcecraft-terminal".to_owned(),
        };
        let receipt = TextGenerationReceipt {
            phase: TextGenerationPhase::Completed,
            conversation_id: record.conversation_id,
            workspace_id: runne_domain::id::WorkspaceId::from_bytes([10; 16]),
            taskrun_id: record.taskrun_id,
            attempt_id: record.execution_attempt_id,
            user_message_id: runne_domain::id::MessageId::from_bytes([14; 16]),
            assistant_message_id: runne_domain::id::MessageId::from_bytes([15; 16]),
            conversation_version: 16,
            taskrun_version: 17,
        };
        assert_eq!(
            conversation_receipt_digest(&record, &receipt),
            bytes("840361b73edfd18fcb71e18bb8227541f2fc850cd1baec90cfa0c4e4eb23e078")
        );
    }
}
