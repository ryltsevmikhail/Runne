struct RejectingEffectTimestampPricing;

struct ReservationPricing;

static RESERVATION_PRICING: ReservationPricing = ReservationPricing;

impl ProviderTerminalPricing for ReservationPricing {
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
        assert_eq!(usage, ProviderUsage::new(512, 1_024, 0, 0).unwrap());
        ProviderPricedUsage::new(50_000, "USD".to_owned())
    }
}

impl ProviderTerminalPricing for RejectingEffectTimestampPricing {
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
        assert_eq!(usage, ProviderUsage::new(512, 1_024, 0, 0).unwrap());
        Err(ProviderTerminalPricingError::Unavailable)
    }
}

#[tokio::test(flavor = "current_thread")]
async fn unavailable_usage_fails_closed_when_effect_timestamp_cannot_be_priced() {
    let fixture = fixture();
    let keyring = fixture.keyring();
    let runtime = RuntimeProviderExecution::new(
        keyring.as_ref(),
        fixture.execution.as_ref(),
        &RejectingEffectTimestampPricing,
        &ALLOWING_GUARD,
        &ALLOWING_REDACTION,
    );
    runtime.preflight_existing_active_key([1; 16], 7).unwrap();
    let events = vec![
        ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
        ProviderStreamEvent::new(1, ProviderStreamEventKind::UsageUnavailable).unwrap(),
        ProviderStreamEvent::new(
            2,
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::RemoteFailed,
                reason: ProviderFinishReason::Error,
            },
        )
        .unwrap(),
    ];
    poll_events(&runtime, &fixture, events).await;

    assert_eq!(
        runtime.finalize_terminal_output(&context(&fixture)),
        Err(RuntimeProviderExecutionError::PricingUnavailable)
    );
    let connection = validated_connection(&fixture);
    for table in [
        "provider_accounting_settlements",
        "provider_terminal_outbox",
    ] {
        assert_eq!(
            connection
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0,
            "unpriceable effect timestamp mutated {table}"
        );
    }
}
