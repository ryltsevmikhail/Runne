use runne_api::{
    ProviderQuotaAvailabilityV1, ProviderQuotaProjectionV1, ProviderQuotaSourceV1,
    ProviderQuotaUnitV1, ProviderQuotaWindowV1,
};
use runne_provider_quota::QuotaStateStore;
use runne_provider_quota::{
    QuotaDecision, QuotaIdentity, QuotaObservationSource, QuotaWindow, QuotaWindowKind,
};

/// Projects only the evidence bound to the selected credential version.
pub(super) fn projection(
    store: &QuotaStateStore,
    provider_id: &str,
    credential_version: Option<u64>,
    now_unix_seconds: u64,
) -> ProviderQuotaProjectionV1 {
    let Some(version) = credential_version else {
        return ProviderQuotaProjectionV1::unknown(provider_id);
    };
    let Ok(identity) = QuotaIdentity::new(provider_id, version) else {
        return ProviderQuotaProjectionV1::unknown(provider_id);
    };
    let Ok(Some(state)) = store.state(&identity) else {
        return ProviderQuotaProjectionV1::unknown(provider_id);
    };
    if let Some(snapshot) = state.snapshot() {
        let windows = snapshot
            .windows()
            .iter()
            .map(project_window)
            .collect::<Vec<_>>();
        let primary = snapshot.windows().iter().find(|window| {
            window.remaining().is_some() || window.limit().is_some() || window.used().is_some()
        });
        let unit = None;
        let decision = state.decision(now_unix_seconds);
        let availability = match decision {
            QuotaDecision::Allow => ProviderQuotaAvailabilityV1::Known,
            QuotaDecision::AllowStale => ProviderQuotaAvailabilityV1::Stale,
            QuotaDecision::PauseExhausted { .. } => ProviderQuotaAvailabilityV1::Exhausted,
            QuotaDecision::AllowUnknown | QuotaDecision::Unavailable => {
                ProviderQuotaAvailabilityV1::Unknown
            }
        };
        let reset_at = if availability == ProviderQuotaAvailabilityV1::Exhausted {
            match decision {
                QuotaDecision::PauseExhausted {
                    reset_at_unix_seconds,
                } => reset_at_unix_seconds,
                _ => None,
            }
        } else {
            primary.and_then(QuotaWindow::reset_at_unix_seconds)
        };
        return ProviderQuotaProjectionV1 {
            provider_id: provider_id.to_owned(),
            source: source(snapshot.source()),
            unit,
            used: primary.and_then(QuotaWindow::used),
            limit: primary.and_then(QuotaWindow::limit),
            remaining: primary.and_then(QuotaWindow::remaining),
            reset_at,
            observed_at: snapshot.observed_at_unix_seconds(),
            availability,
            windows,
        };
    }
    let usage = state.local_usage();
    let Some(used) = usage
        .input_tokens()
        .checked_add(usage.output_tokens())
        .filter(|value| *value > 0)
    else {
        return ProviderQuotaProjectionV1::unknown(provider_id);
    };
    ProviderQuotaProjectionV1 {
        provider_id: provider_id.to_owned(),
        source: ProviderQuotaSourceV1::LocalUsage,
        unit: Some(ProviderQuotaUnitV1::Tokens),
        used: Some(used),
        limit: None,
        remaining: None,
        reset_at: None,
        observed_at: usage.last_observed_at_unix_seconds().unwrap_or(0),
        availability: ProviderQuotaAvailabilityV1::Unknown,
        windows: Vec::new(),
    }
}

fn source(source: QuotaObservationSource) -> ProviderQuotaSourceV1 {
    match source {
        QuotaObservationSource::ProviderApi => ProviderQuotaSourceV1::ProviderReported,
        QuotaObservationSource::LocalConfig => ProviderQuotaSourceV1::LocalConfig,
        QuotaObservationSource::Unknown => ProviderQuotaSourceV1::Unknown,
    }
}

fn project_window(window: &QuotaWindow) -> ProviderQuotaWindowV1 {
    ProviderQuotaWindowV1 {
        kind: match window.kind() {
            QuotaWindowKind::TokenQuotaUnspecified => "TokenQuotaUnspecified",
            QuotaWindowKind::FiveHourTime => "FiveHourTime",
            QuotaWindowKind::WeeklyTime => "WeeklyTime",
            QuotaWindowKind::MonthlyTime => "MonthlyTime",
        }
        .to_owned(),
        used: window.used(),
        limit: window.limit(),
        remaining: window.remaining(),
        percent_used: window.percent_used(),
        reset_at: window.reset_at_unix_seconds(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider_quota::{QuotaObservationSource, QuotaSnapshot};

    #[test]
    fn provider_window_does_not_fabricate_a_counter_unit() {
        let store = QuotaStateStore::new();
        let identity = QuotaIdentity::new("zai", 1).unwrap();
        let window = QuotaWindow::new(
            QuotaWindowKind::FiveHourTime,
            None,
            None,
            None,
            Some(42),
            None,
        )
        .unwrap();
        let snapshot = QuotaSnapshot::new(
            identity,
            QuotaObservationSource::ProviderApi,
            100,
            vec![window],
        )
        .unwrap();
        runne_provider_quota::QuotaEvidenceSink::record_snapshot(&store, snapshot).unwrap();
        let projection = projection(&store, "zai", Some(1), 100);
        assert_eq!(projection.unit, None);
        assert_eq!(projection.windows[0].percent_used, Some(42));
        assert_eq!(projection.windows[0].kind, "FiveHourTime");
    }

    #[test]
    fn exhausted_window_after_reset_is_unknown_until_refreshed() {
        let store = QuotaStateStore::new();
        let identity = QuotaIdentity::new("zai", 1).unwrap();
        let window = QuotaWindow::new(
            QuotaWindowKind::FiveHourTime,
            Some(10),
            Some(10),
            Some(0),
            None,
            Some(110),
        )
        .unwrap();
        let snapshot = QuotaSnapshot::new(
            identity,
            QuotaObservationSource::ProviderApi,
            100,
            vec![window],
        )
        .unwrap();
        runne_provider_quota::QuotaEvidenceSink::record_snapshot(&store, snapshot).unwrap();
        assert_eq!(
            projection(&store, "zai", Some(1), 111).availability,
            ProviderQuotaAvailabilityV1::Unknown
        );
    }

    #[test]
    fn projection_isolated_by_active_credential_version() {
        let store = QuotaStateStore::new();
        let identity = QuotaIdentity::new("zai", 1).unwrap();
        runne_provider_quota::QuotaEvidenceSink::record_usage(&store, &identity, 2, 3, 100)
            .unwrap();
        assert_eq!(
            projection(&store, "zai", Some(2), 100).availability,
            ProviderQuotaAvailabilityV1::Unknown
        );
        assert_eq!(projection(&store, "zai", Some(1), 100).used, Some(5));
    }
}
