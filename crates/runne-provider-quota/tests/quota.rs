use runne_provider_quota::{
    QuotaAuthHeaderKind, QuotaAvailability, QuotaDecision, QuotaEndpointScope, QuotaIdentity,
    QuotaModelError, QuotaObservationSource, QuotaParseError, QuotaProvider, QuotaRefreshStatus,
    QuotaRequestDescriptor, QuotaSnapshot, QuotaState, QuotaWindow, QuotaWindowKind,
    QwenRateLimitEvidence, ZaiErrorDisposition, classify_zai_error_code, parse_qwen_token_plan,
    parse_retry_after, parse_zai_error_code, parse_zai_limits,
};

fn identity(version: u64) -> QuotaIdentity {
    QuotaIdentity::new("zai", version).unwrap()
}

fn window(remaining: Option<u64>, percent: Option<u8>) -> QuotaWindow {
    QuotaWindow::new(
        QuotaWindowKind::TokenQuotaUnspecified,
        remaining.map(|value| 100 - value),
        remaining.map(|_| 100),
        remaining,
        percent,
        None,
    )
    .unwrap()
}

#[test]
fn descriptors_pin_endpoints_and_auth_without_credentials() {
    let zai = QuotaRequestDescriptor::zai_global();
    assert_eq!(zai.provider(), QuotaProvider::ZaiGlobal);
    assert_eq!(
        zai.endpoint(),
        Some("https://api.z.ai/api/monitor/usage/quota/limit")
    );
    assert_eq!(zai.auth_header(), QuotaAuthHeaderKind::RawAuthorization);
    assert_eq!(zai.scope(), QuotaEndpointScope::ProviderApi);
    let qwen = QuotaRequestDescriptor::qwen_token_plan_individual();
    assert_eq!(qwen.endpoint(), None);
    assert_eq!(qwen.scope(), QuotaEndpointScope::ConsoleRequired);
}

#[test]
fn parses_zai_percentages_without_fabricating_remaining_or_reset() {
    let body = br#"{"data":{"limits":[{"type":"TOKENS_LIMIT","percentage":25,"currentValue":123,"usage":999},{"type":"TIME_LIMIT","percentage":4,"currentValue":5,"usage":6}],"extra":"ignored"}}"#;
    let snapshot = parse_zai_limits(identity(1), 100, body).unwrap();
    assert_eq!(snapshot.source(), QuotaObservationSource::ProviderApi);
    assert_eq!(snapshot.availability(), QuotaAvailability::Unknown);
    assert_eq!(snapshot.windows()[0].percent_used(), Some(25));
    assert_eq!(snapshot.windows()[0].remaining(), None);
    assert_eq!(snapshot.windows()[0].reset_at_unix_seconds(), None);
}

#[test]
fn unknown_zai_schema_and_invalid_percentage_fail_closed() {
    assert_eq!(
        parse_zai_limits(
            identity(1),
            100,
            br#"{"data":{"limits":[{"type":"NEW_LIMIT","percentage":1}]}}"#
        ),
        Err(QuotaParseError::UnknownSchema)
    );
    assert_eq!(
        parse_zai_limits(
            identity(1),
            100,
            br#"{"data":{"limits":[{"type":"TOKENS_LIMIT","percentage":101}]}}"#
        ),
        Err(QuotaParseError::Invalid)
    );
    assert_eq!(
        parse_qwen_token_plan(),
        Err(QuotaParseError::ConsoleRequired)
    );
    let valid = br#"{"data":{"limits":[{"type":"TOKENS_LIMIT","percentage":1}]}}"#;
    assert_eq!(
        parse_zai_limits(identity(1), 100, &[valid.as_slice(), b" trailing"].concat()),
        Err(QuotaParseError::UnknownSchema)
    );
    assert_eq!(
        parse_zai_limits(
            identity(1),
            100,
            br#"{"data":{"limits":[]},"data":{"limits":[{"type":"TOKENS_LIMIT","percentage":1}]}}"#
        ),
        Err(QuotaParseError::UnknownSchema)
    );
    assert_eq!(
        parse_zai_limits(
            identity(1),
            100,
            br#"{"success":false,"data":{"limits":[{"type":"TOKENS_LIMIT","percentage":1}]}}"#
        ),
        Err(QuotaParseError::UnknownSchema)
    );
    assert_eq!(
        parse_zai_limits(
            identity(1),
            100,
            br#"{"status":"failed","data":{"limits":[{"type":"TOKENS_LIMIT","percentage":1}]}}"#
        ),
        Err(QuotaParseError::UnknownSchema)
    );
}

#[test]
fn state_distinguishes_unknown_stale_and_exhausted_and_preserves_exhaustion() {
    let mut state = QuotaState::new(identity(1), 60);
    assert_eq!(state.decision(100), QuotaDecision::AllowUnknown);
    let exhausted = QuotaSnapshot::new(
        identity(1),
        QuotaObservationSource::ProviderApi,
        100,
        vec![window(Some(0), Some(100))],
    )
    .unwrap();
    state.apply_snapshot(exhausted).unwrap();
    assert_eq!(
        state.decision(101),
        QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: None
        }
    );
    let unknown = QuotaSnapshot::new(
        identity(1),
        QuotaObservationSource::ProviderApi,
        101,
        vec![window(None, Some(50))],
    )
    .unwrap();
    state.apply_snapshot(unknown).unwrap();
    assert_eq!(
        state.decision(101),
        QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: None
        }
    );
    state.record_refresh_failure(QuotaRefreshStatus::UnknownSchema);
    assert_eq!(
        state.decision(101),
        QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: None
        }
    );
}

#[test]
fn state_handles_freshness_time_regression_rotation_and_atomic_usage() {
    let mut state = QuotaState::new(identity(1), 60);
    let known = QuotaSnapshot::new(
        identity(1),
        QuotaObservationSource::LocalConfig,
        100,
        vec![
            QuotaWindow::new(
                QuotaWindowKind::TokenQuotaUnspecified,
                Some(20),
                Some(100),
                Some(80),
                None,
                Some(200),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    state.apply_snapshot(known.clone()).unwrap();
    assert_eq!(state.decision(99), QuotaDecision::AllowStale);
    assert_eq!(state.decision(161), QuotaDecision::AllowStale);
    assert_eq!(
        state.apply_snapshot(known),
        Err(QuotaModelError::ObservationRegressed)
    );
    state.record_usage(&identity(1), 4, 5, 100).unwrap();
    assert_eq!(state.local_usage().input_tokens(), 4);
    assert_eq!(
        state.record_usage(&identity(1), u64::MAX, 1, 101),
        Err(QuotaModelError::UsageOverflow)
    );
    assert_eq!(state.local_usage().input_tokens(), 4);
    let rotated = QuotaSnapshot::new(
        identity(2),
        QuotaObservationSource::ProviderApi,
        1,
        vec![window(Some(10), None)],
    )
    .unwrap();
    state.apply_snapshot(rotated).unwrap();
    assert_eq!(state.identity().credential_version(), 2);
    assert_eq!(state.local_usage().input_tokens(), 0);
}

#[test]
fn retry_and_error_classification_is_bounded_and_nonsecret() {
    assert_eq!(parse_retry_after("30"), Some(30));
    assert_eq!(parse_retry_after("86401"), None);
    assert_eq!(parse_retry_after("Wed, 21 Oct"), None);
    assert_eq!(
        QwenRateLimitEvidence::from_status(429, Some("7"))
            .unwrap()
            .retry_after_seconds(),
        Some(7)
    );
    assert!(QwenRateLimitEvidence::from_status(429, None).is_some());
    assert!(QwenRateLimitEvidence::from_status(200, Some("7")).is_none());
    assert_eq!(
        classify_zai_error_code(1308),
        ZaiErrorDisposition::Exhausted
    );
    assert_eq!(
        classify_zai_error_code(1305),
        ZaiErrorDisposition::RateLimited
    );
    assert_eq!(classify_zai_error_code(9999), ZaiErrorDisposition::Unknown);
    assert_eq!(
        parse_zai_error_code(br#"{"error":{"code":1308,"message":"redacted"}}"#),
        Some(1308)
    );
    assert_eq!(parse_zai_error_code(br#"{"code":1308,"code":1305}"#), None);
}
