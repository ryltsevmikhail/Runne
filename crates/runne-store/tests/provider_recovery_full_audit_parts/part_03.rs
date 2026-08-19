#[test]
fn terminal_request_commits_after_reopen_without_rewriting_journal() {
    let (database, claim, request) = terminal_setup("recovery-terminal-before-settlement", 5);
    let before = database.connection();
    assert_eq!(table_count(&before, "provider_stream_journal"), 1);
    assert_eq!(table_count(&before, "provider_accounting_settlements"), 0);
    assert_eq!(table_count(&before, "provider_terminal_outbox"), 0);
    drop(before);

    let settlement_digest = *request.settlement_digest();
    let reopened = database.execution();
    assert_eq!(
        reopened.load_encrypted_events(claim.attempt_id).unwrap().len(),
        1
    );
    assert_eq!(
        reopened.commit_terminal(&request),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );

    let after = database.connection();
    assert_eq!(table_count(&after, "provider_accounting_settlements"), 1);
    assert_eq!(table_count(&after, "provider_terminal_outbox"), 1);
    let usage = request.usage();
    assert_eq!(
        after
            .query_row(
                "SELECT settlement_digest, input_tokens, output_tokens, cached_input_tokens,
                        reasoning_output_tokens, charge_micros, currency
                 FROM provider_accounting_settlements WHERE dispatch_attempt_id = ?1",
                [claim.attempt_id.as_bytes().as_slice()],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .unwrap(),
        (
            settlement_digest.to_vec(),
            i64::try_from(usage.input_tokens()).unwrap(),
            i64::try_from(usage.output_tokens()).unwrap(),
            i64::try_from(usage.cached_input_tokens()).unwrap(),
            i64::try_from(usage.reasoning_output_tokens()).unwrap(),
            i64::try_from(request.charge_micros()).unwrap(),
            request.currency().to_owned(),
        )
    );
    assert_eq!(
        after
            .query_row(
                "SELECT settlement_digest FROM provider_terminal_outbox WHERE dispatch_attempt_id = ?1",
                [claim.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .unwrap(),
        settlement_digest,
    );
}
