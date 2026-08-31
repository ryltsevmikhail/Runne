
struct DenyingGuard;

impl ProhibitedContentPort for DenyingGuard {
    fn inspect(
        &self,
        _boundary: CanonicalContentBoundary,
        _bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        Ok(ContentDisposition::Prohibited { policy_epoch: 1 })
    }
}

pub(crate) struct FixedPricing;

impl ProviderTerminalPricing for FixedPricing {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        assert_eq!(pricing_revision_digest, &[3; 32]);
        assert_eq!(profile_digest, &[2; 32]);
        assert_eq!(usage, ProviderUsage::new(500, 900, 0, 0).unwrap());
        ProviderPricedUsage::new(40_000, "USD".to_owned())
    }
}

struct ZeroInputPricing;

impl ProviderTerminalPricing for ZeroInputPricing {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        assert_eq!(pricing_revision_digest, &[3; 32]);
        assert_eq!(profile_digest, &[2; 32]);
        assert_eq!(usage, ProviderUsage::new(0, 900, 0, 0).unwrap());
        ProviderPricedUsage::new(30_000, "USD".to_owned())
    }
}

static FIXED_PRICING: FixedPricing = FixedPricing;
static ZERO_INPUT_PRICING: ZeroInputPricing = ZeroInputPricing;
static ALLOWING_GUARD: AllowingGuard = AllowingGuard;
static DENYING_GUARD: DenyingGuard = DenyingGuard;

pub(crate) fn runtime<'a, S>(
    keyring: &'a MemoryKeyring,
    store: &'a S,
) -> RuntimeProviderExecution<'a, MemoryKeyring, S, FixedPricing>
where
    S: ProviderExecutionStore + ProviderTerminalPersistence,
{
    RuntimeProviderExecution::new(
        keyring,
        store,
        &FIXED_PRICING,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn aead_journal_recovers_exact_event_and_plaintext_is_absent_from_database_files() {
    const MARKER: &str = "provider-journal-plaintext-marker-71";
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: MARKER.to_owned(),
            },
        )
        .unwrap(),
    ];

    poll_events(&runtime, &fixture, events.clone()).await;
    assert_eq!(runtime.recover_events(fixture.attempt_id).unwrap(), events);
    for path in [
        fixture.path.clone(),
        fixture.path.with_extension("sqlite-wal"),
        fixture.path.with_extension("sqlite-shm"),
    ] {
        let bytes = std::fs::read(path).unwrap_or_default();
        assert!(
            !bytes
                .windows(MARKER.len())
                .any(|window| window == MARKER.as_bytes())
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn corrupt_ciphertext_and_missing_retired_key_fail_closed() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    let first_key = runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "recover-me".to_owned(),
            },
        )
        .unwrap(),
    ];
    poll_events(&runtime, &fixture, events.clone()).await;
    runtime.create_and_activate_key([1; 16], 7, 2).unwrap();
    assert_eq!(runtime.recover_events(fixture.attempt_id).unwrap(), events);

    keyring.remove_without_proof(
        ProviderJournalKeyRef::new(
            first_key.key_id(),
            first_key.key_version(),
            first_key.runtime_authority_id(),
            first_key.database_generation(),
        )
        .unwrap(),
    );
    assert_eq!(
        runtime.recover_events(fixture.attempt_id),
        Err(RuntimeProviderExecutionError::JournalKeyUnavailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn terminal_output_is_encrypted_recoverable_and_settled_only_after_receipt() {
    const OUTPUT: &[u8] = b"assembled-provider-output-marker-81";
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = runtime(&keyring, fixture.execution.as_ref());
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events(std::str::from_utf8(OUTPUT).unwrap()),
    )
    .await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    let pending = runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].output(), OUTPUT);
    assert!(!format!("{:?}", pending[0]).contains(std::str::from_utf8(OUTPUT).unwrap()));

    runtime
        .acknowledge_terminal_output(pending[0].record().outbox_id, [32; 32])
        .unwrap();
    assert!(
        runtime
            .recover_pending_terminal_outputs()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn zero_input_reservation_admits_streams_and_settles_completed_usage() {
    let fixture = fixture_with_input_tokens(0);
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &ZERO_INPUT_PRICING,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(
            1,
            ProviderStreamEventKind::TextDelta {
                text: "zero-input-output".to_owned(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(0, 900, 0, 0).unwrap(),
            },
        )
        .unwrap(),
        ProviderStreamEvent::new(
            3,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: ProviderFinishReason::Stop,
            },
        )
        .unwrap(),
    ];
    poll_events(&runtime, &fixture, events).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection
            .query_row(
                "SELECT input_tokens, output_tokens, charge_micros
                 FROM provider_accounting_settlements",
                [],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .unwrap(),
        (0, 900, 30_000)
    );
    let reservations = connection
        .prepare(
            "SELECT dimension, settled_amount
             FROM provider_budget_reservations ORDER BY dimension",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert_eq!(reservations, vec![(1, 900), (2, 30_000)]);
}
