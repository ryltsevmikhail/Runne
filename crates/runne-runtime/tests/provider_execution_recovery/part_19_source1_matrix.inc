struct UnavailableSource1Pricing;
struct InvalidSource1Pricing;
struct CurrencyMismatchSource1Pricing;

macro_rules! exact_usage_pricing_prelude {
    ($pricing:ty, $currency:expr) => {
        impl ProviderTerminalPricing for $pricing {
            fn price_terminal_usage(
                &self,
                pricing_revision_digest: &[u8; 32],
                profile_digest: &[u8; 32],
                effect_started_at: i64,
                usage: ProviderUsage,
            ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
                assert_eq!(pricing_revision_digest, &[3; 32]);
                assert_eq!(profile_digest, &[2; 32]);
                assert!(effect_started_at > 0);
                assert_eq!(usage, ProviderUsage::new(500, 900, 0, 0).unwrap());
                ProviderPricedUsage::new(40_000, $currency.to_owned())
            }
        }
    };
}

impl ProviderTerminalPricing for UnavailableSource1Pricing {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        assert_eq!(pricing_revision_digest, &[3; 32]);
        assert_eq!(profile_digest, &[2; 32]);
        assert!(effect_started_at > 0);
        assert_eq!(usage, ProviderUsage::new(500, 900, 0, 0).unwrap());
        Err(ProviderTerminalPricingError::Unavailable)
    }
}

impl ProviderTerminalPricing for InvalidSource1Pricing {
    fn price_terminal_usage(
        &self,
        pricing_revision_digest: &[u8; 32],
        profile_digest: &[u8; 32],
        effect_started_at: i64,
        usage: ProviderUsage,
    ) -> Result<ProviderPricedUsage, ProviderTerminalPricingError> {
        assert_eq!(pricing_revision_digest, &[3; 32]);
        assert_eq!(profile_digest, &[2; 32]);
        assert!(effect_started_at > 0);
        assert_eq!(usage, ProviderUsage::new(500, 900, 0, 0).unwrap());
        ProviderPricedUsage::new(u64::MAX, "USD".to_owned())
    }
}

exact_usage_pricing_prelude!(CurrencyMismatchSource1Pricing, "EUR");

async fn assert_unknown_usage_reason<P: ProviderTerminalPricing>(pricing: &P, reason: i64) {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        pricing,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    poll_events(
        &runtime,
        &fixture,
        successful_events("source1-unpriced-output"),
    )
    .await;
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Committed)
    );
    let before_replay = sql_snapshot(&validated_connection(&fixture));
    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Ok(ProviderTerminalCommitOutcome::Replayed)
    );
    assert_eq!(sql_snapshot(&validated_connection(&fixture)), before_replay);
    let pending = runtime.recover_pending_terminal_outputs().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].output(), b"source1-unpriced-output");
    let connection = validated_connection(&fixture);
    assert_eq!(
        connection.query_row(
            "SELECT accounting_reason,usage_present,input_tokens,output_tokens,terminal_disposition
             FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1",
            [fixture.attempt_id.as_bytes().as_slice()],
            |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?, row.get::<_, i64>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?)),
        ).unwrap(),
        (reason, 1, 500, 900, 1)
    );
    assert_eq!(
        connection
            .query_row(
                "SELECT COUNT(*) FROM provider_accounting_settlements WHERE dispatch_attempt_id=?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
        0,
        "an Unknown terminal preserves usage without claiming finance"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn source1_retains_exact_usage_for_all_unpriceable_reasons_and_replays_publication() {
    assert_unknown_usage_reason(&UnavailableSource1Pricing, 2).await;
    assert_unknown_usage_reason(&InvalidSource1Pricing, 3).await;
    assert_unknown_usage_reason(&CurrencyMismatchSource1Pricing, 4).await;
}

#[tokio::test(flavor = "current_thread")]
async fn failed_and_incomplete_partial_output_never_create_finance_or_outbox() {
    for disposition in [
        ProviderTerminalDisposition::RemoteFailed,
        ProviderTerminalDisposition::RemoteIncomplete,
    ] {
        let fixture = fixture();
        let keyring = fixture.keyring();
        let runtime = runtime(&keyring, fixture.execution.as_ref());
        runtime.preflight_existing_active_key([1; 16], 7).unwrap();
        let events = vec![
            ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
            ProviderStreamEvent::new(
                1,
                ProviderStreamEventKind::TextDelta {
                    text: "unapplied partial provider output".into(),
                },
            )
            .unwrap(),
            ProviderStreamEvent::new(2, ProviderStreamEventKind::UsageUnavailable).unwrap(),
            ProviderStreamEvent::new(
                3,
                ProviderStreamEventKind::Finished {
                    disposition,
                    reason: ProviderFinishReason::Error,
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
        for table in [
            "provider_accounting_settlements",
            "provider_terminal_outbox",
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{disposition:?} partial output must not create {table}"
            );
        }
        assert_eq!(
            connection.query_row(
                "SELECT usage_present,accounting_reason FROM provider_unknown_terminal_receipts WHERE dispatch_attempt_id=?1",
                [fixture.attempt_id.as_bytes().as_slice()],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            ).unwrap(),
            (0, 1)
        );
    }
}
