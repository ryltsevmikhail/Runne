#[tokio::test(flavor = "current_thread")]
async fn exact_usage_without_its_pinned_price_is_retained_without_known_settlement() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let openai_profile = OpenAiResponsesTextProfile::from_json(include_bytes!(
        "../../../../docs/profiles/openai-responses-text-v1.json"
    ))
    .unwrap();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &openai_profile,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events("exact-pricing-mismatch"),
    )
    .await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(runne_application::provider::ProviderTerminalCommitOutcome::Committed)
    );
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_accounting_settlements",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        0,
        "unpriceable usage must not create known accounting"
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_terminal_outbox WHERE dispatch_attempt_id=?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
        1,
        "a publishable factual Completed result remains in the existing output control plane"
    );
    assert_eq!(
        connection.query_row("SELECT usage_present,input_tokens,output_tokens,cached_input_tokens,reasoning_output_tokens,accounting_reason FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1", [fixture.attempt_id.as_bytes().as_slice()], |row| Ok((row.get::<_,i64>(0)?,row.get::<_,Option<i64>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,Option<i64>>(3)?,row.get::<_,Option<i64>>(4)?,row.get::<_,i64>(5)?))).unwrap(),
        (1,Some(500),Some(900),Some(0),Some(0),2)
    );
    assert_eq!(
        connection
            .prepare("SELECT state,settled_amount,released_at FROM provider_budget_reservations ORDER BY dimension")
            .unwrap()
            .query_map([], |row| Ok((row.get::<_, i64>(0)?,row.get::<_, Option<i64>>(1)?,row.get::<_, Option<i64>>(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap(),
        vec![(1, None, None), (1, None, None)],
        "unpriceable actual usage must leave both original reserves held"
    );
}
