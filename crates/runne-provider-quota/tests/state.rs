use runne_provider_quota::{
    QuotaDecision, QuotaEvidenceSink, QuotaIdentity, QuotaObservationSource, QuotaSnapshot,
    QuotaState, QuotaStateStore, QuotaWindow, QuotaWindowKind,
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
fn exhausted_window_allows_unknown_after_attested_reset() {
    let mut state = QuotaState::new(identity(1), 60);
    let exhausted = QuotaSnapshot::new(
        identity(1),
        QuotaObservationSource::ProviderApi,
        100,
        vec![
            QuotaWindow::new(
                QuotaWindowKind::TokenQuotaUnspecified,
                Some(100),
                Some(100),
                Some(0),
                Some(100),
                Some(200),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    state.apply_snapshot(exhausted).unwrap();
    assert!(matches!(
        state.decision(199),
        QuotaDecision::PauseExhausted { .. }
    ));
    assert_eq!(state.decision(200), QuotaDecision::AllowUnknown);
}

#[test]
fn exhausted_windows_use_latest_known_reset_and_hide_unknown_reset() {
    let mut state = QuotaState::new(identity(1), 60);
    let snapshot = QuotaSnapshot::new(
        identity(1),
        QuotaObservationSource::ProviderApi,
        100,
        vec![
            QuotaWindow::new(
                QuotaWindowKind::TokenQuotaUnspecified,
                Some(100),
                Some(100),
                Some(0),
                Some(100),
                Some(200),
            )
            .unwrap(),
            QuotaWindow::new(
                QuotaWindowKind::MonthlyTime,
                Some(100),
                Some(100),
                Some(0),
                Some(100),
                Some(300),
            )
            .unwrap(),
        ],
    )
    .unwrap();
    state.apply_snapshot(snapshot).unwrap();
    assert_eq!(
        state.decision(101),
        QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: Some(300)
        }
    );

    let unknown_reset = QuotaSnapshot::new(
        identity(1),
        QuotaObservationSource::ProviderApi,
        102,
        vec![window(Some(0), Some(100))],
    )
    .unwrap();
    state.apply_snapshot(unknown_reset).unwrap();
    assert_eq!(
        state.decision(103),
        QuotaDecision::PauseExhausted {
            reset_at_unix_seconds: None
        }
    );
}

#[test]
fn state_store_binds_usage_to_provider_and_credential_version() {
    let store = QuotaStateStore::new();
    let first = identity(1);
    QuotaEvidenceSink::record_usage(&store, &first, 3, 4, 100).unwrap();
    let state = store.state(&first).unwrap().unwrap();
    assert_eq!(state.local_usage().input_tokens(), 3);
    assert_eq!(state.local_usage().output_tokens(), 4);
    assert!(store.state(&identity(2)).unwrap().is_none());
}
