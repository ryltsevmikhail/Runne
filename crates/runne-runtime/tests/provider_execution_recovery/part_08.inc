use sha2::{Digest, Sha256};

const OUTBOX_DOMAIN: &[u8] = b"GOCODE_PROVIDER_OUTBOX_ID_V1\0";
const SETTLEMENT_DOMAIN: &[u8] = b"GOCODE_PROVIDER_SETTLEMENT_V2\0";

fn expected_outbox_id(context: &ProviderEventJournalContext, sequence: u64) -> [u8; 16] {
    let mut hasher = Sha256::new();
    hasher.update(OUTBOX_DOMAIN);
    hasher.update(context.attempt_id.as_bytes());
    hasher.update(context.fencing_token.to_be_bytes());
    hasher.update(context.runtime_generation.to_be_bytes());
    hasher.update(sequence.to_be_bytes());
    let digest: [u8; 32] = hasher.finalize().into();
    let mut id = [0; 16];
    id.copy_from_slice(&digest[..16]);
    if id == [0; 16] { id[15] = 1; }
    id
}

fn expected_settlement_digest(context: &ProviderEventJournalContext, output: &[u8]) -> [u8; 32] {
    let usage = ProviderUsage::new(500, 900, 0, 0).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(SETTLEMENT_DOMAIN);
    hasher.update(context.attempt_id.as_bytes());
    hasher.update(context.fencing_token.to_be_bytes());
    hasher.update(context.runtime_generation.to_be_bytes());
    hasher.update(context.profile_digest);
    hasher.update([3; 32]);
    hasher.update(3_u64.to_be_bytes());
    hasher.update(Sha256::digest(output));
    hasher.update(usage.input_tokens().to_be_bytes());
    hasher.update(usage.output_tokens().to_be_bytes());
    hasher.update(usage.cached_input_tokens().to_be_bytes());
    hasher.update(usage.reasoning_output_tokens().to_be_bytes());
    hasher.update([0]);
    hasher.update([1]);
    hasher.update(40_000_u64.to_be_bytes());
    hasher.update(b"USD");
    hasher.finalize().into()
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_journal_reopen_finalizes_with_stable_runtime_identities() {
    let fixture = fixture();
    let keyring = MemoryKeyring::default();
    let output = b"runtime-b6-reopen-output";
    let context = context(&fixture);
    {
        let writer = runtime(&keyring, fixture.execution.as_ref());
        writer.create_and_activate_key([1; 16], 7, 1).unwrap();
        poll_events(&writer, &fixture, successful_events(std::str::from_utf8(output).unwrap())).await;
        let before = validated_connection(&fixture);
        assert_eq!(before.query_row("SELECT state FROM provider_dispatch_attempts", [], |r| r.get::<_, i64>(0)).unwrap(), 3);
        assert_eq!(before.query_row("SELECT COUNT(*) FROM provider_stream_journal WHERE terminal = 1", [], |r| r.get::<_, i64>(0)).unwrap(), 1);
        assert_eq!(before.query_row("SELECT COUNT(*) FROM provider_accounting_settlements", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
        assert_eq!(before.query_row("SELECT COUNT(*) FROM provider_terminal_outbox", [], |r| r.get::<_, i64>(0)).unwrap(), 0);
    }
    let path = fixture.path.clone();
    let identity = fixture.identity;
    drop(fixture.execution);
    let store = validated_reopen::open_provider_execution(path.to_str().unwrap(), identity).unwrap();
    let reopened = runtime(&keyring, &store);
    reopened.preflight_existing_active_key([1; 16], 7).unwrap();
    assert_eq!(reopened.recover_events(context.attempt_id).unwrap().len(), 4);
    assert_eq!(reopened.finalize_terminal_output(&context), Ok(ProviderTerminalCommitOutcome::Committed));
    let after = validated_reopen::open_validated_connection(path.to_str().unwrap(), identity).unwrap();
    assert_eq!(after.query_row("SELECT outbox_id FROM provider_terminal_outbox", [], |r| r.get::<_, Vec<u8>>(0)).unwrap(), expected_outbox_id(&context, 3));
    assert_eq!(after.query_row("SELECT settlement_digest FROM provider_terminal_outbox", [], |r| r.get::<_, Vec<u8>>(0)).unwrap(), expected_settlement_digest(&context, output));
    assert_eq!(after.query_row("SELECT input_tokens, output_tokens, charge_micros, currency FROM provider_accounting_settlements", [], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)?, r.get::<_, i64>(2)?, r.get::<_, String>(3)?))).unwrap(), (500, 900, 40_000, "USD".to_owned()));
    let snapshot = sql_snapshot(&after);
    drop(after);
    assert_eq!(reopened.finalize_terminal_output(&context), Ok(ProviderTerminalCommitOutcome::Replayed));
    assert_eq!(sql_snapshot(&validated_reopen::open_validated_connection(path.to_str().unwrap(), identity).unwrap()), snapshot);
}
