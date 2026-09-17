use runne_provider::{ProviderStreamEvent, ProviderStreamEventKind};
use runne_provider_quota::{QuotaDecision, QuotaEvidenceSink, QuotaIdentity};
use runne_provider_quota::{
    QuotaObservationSource, QuotaRefreshStatus, QuotaSnapshot, QuotaWindow, QuotaWindowKind,
    ZaiErrorDisposition, classify_zai_error_code, parse_zai_error_code,
};
use std::sync::Arc;

/// Records normalized token usage without coupling dispatch to quota storage.
pub fn record_usage(
    sink: Option<&Arc<dyn QuotaEvidenceSink>>,
    provider_id: &str,
    credential_version: u64,
    events: &[ProviderStreamEvent],
) {
    let Some(sink) = sink else { return };
    let Ok(identity) = QuotaIdentity::new(provider_id, credential_version) else {
        return;
    };
    let observed_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs().max(1));
    for event in events {
        if let ProviderStreamEventKind::Usage { usage } = event.kind() {
            let _ = sink.record_usage(
                &identity,
                usage.input_tokens(),
                usage.output_tokens(),
                observed_at,
            );
        }
    }
}

/// Rejects an exhausted credential before secure-store materialization.
pub fn rejects_exhausted(
    sink: Option<&Arc<dyn QuotaEvidenceSink>>,
    provider_id: &str,
    credential_version: u64,
    now_unix_seconds: u64,
) -> bool {
    let Some(sink) = sink else { return false };
    let Ok(identity) = QuotaIdentity::new(provider_id, credential_version) else {
        return false;
    };
    matches!(
        sink.admission(&identity, now_unix_seconds),
        QuotaDecision::PauseExhausted { .. } | QuotaDecision::Unavailable
    )
}

/// Records only verified structured Z.ai quota error evidence.
pub fn record_zai_error(
    sink: Option<&Arc<dyn QuotaEvidenceSink>>,
    provider_id: &str,
    credential_version: u64,
    observed_at_unix_seconds: u64,
    body: &[u8],
) {
    let Some(sink) = sink else { return };
    if provider_id != "zai" && provider_id != "zai-coding-cn" {
        return;
    }
    let Some(code) = parse_zai_error_code(body) else {
        return;
    };
    let Ok(identity) = QuotaIdentity::new(provider_id, credential_version) else {
        return;
    };
    match classify_zai_error_code(code) {
        ZaiErrorDisposition::Exhausted => {
            let Ok(snapshot) = QuotaSnapshot::new(
                identity,
                QuotaObservationSource::ProviderApi,
                observed_at_unix_seconds,
                vec![
                    QuotaWindow::new(
                        QuotaWindowKind::TokenQuotaUnspecified,
                        None,
                        None,
                        Some(0),
                        None,
                        None,
                    )
                    .unwrap(),
                ],
            ) else {
                return;
            };
            let _ = sink.record_snapshot(snapshot);
        }
        ZaiErrorDisposition::RateLimited => {
            let _ = sink.record_refresh_failure(
                &identity,
                QuotaRefreshStatus::RateLimited {
                    retry_after_seconds: None,
                },
            );
        }
        ZaiErrorDisposition::Expired | ZaiErrorDisposition::Restricted => {
            let _ = sink.record_refresh_failure(&identity, QuotaRefreshStatus::Unauthorized);
        }
        ZaiErrorDisposition::Unknown => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_provider_quota::{
        QuotaObservationSource, QuotaSnapshot, QuotaStateStore, QuotaWindow, QuotaWindowKind,
    };

    #[test]
    fn exhausted_state_is_rejected_before_materialization() {
        let store = QuotaStateStore::new();
        let identity = QuotaIdentity::new("zai", 1).unwrap();
        let snapshot = QuotaSnapshot::new(
            identity,
            QuotaObservationSource::ProviderApi,
            100,
            vec![
                QuotaWindow::new(
                    QuotaWindowKind::TokenQuotaUnspecified,
                    Some(100),
                    Some(100),
                    Some(0),
                    Some(100),
                    None,
                )
                .unwrap(),
            ],
        )
        .unwrap();
        store.record_snapshot(snapshot).unwrap();
        let sink: Arc<dyn QuotaEvidenceSink> = Arc::new(store);
        assert!(rejects_exhausted(Some(&sink), "zai", 1, 101));
    }

    #[test]
    fn structured_zai_exhaustion_is_recorded_without_message_text() {
        let store = QuotaStateStore::new();
        let sink: Arc<dyn QuotaEvidenceSink> = Arc::new(store.clone());
        record_zai_error(
            Some(&sink),
            "zai",
            1,
            101,
            br#"{"code":1308,"message":"secret provider detail"}"#,
        );
        let identity = QuotaIdentity::new("zai", 1).unwrap();
        let state = store.state(&identity).unwrap().unwrap();
        assert_eq!(
            state.snapshot().map(QuotaSnapshot::availability),
            Some(runne_provider_quota::QuotaAvailability::Exhausted)
        );
    }

    #[test]
    fn structured_zai_error_does_not_block_another_provider() {
        let store = QuotaStateStore::new();
        let sink: Arc<dyn QuotaEvidenceSink> = Arc::new(store.clone());
        record_zai_error(
            Some(&sink),
            "qwen-token-plan-individual",
            1,
            101,
            br#"{"code":1308}"#,
        );
        let identity = QuotaIdentity::new("qwen-token-plan-individual", 1).unwrap();
        assert!(store.state(&identity).unwrap().is_none());
    }

    #[test]
    fn usage_is_recorded_for_qwen_as_local_evidence() {
        let store = QuotaStateStore::new();
        let sink: Arc<dyn QuotaEvidenceSink> = Arc::new(store.clone());
        let usage = runne_provider::ProviderUsage::new(4, 3, 0, 0).unwrap();
        let event = ProviderStreamEvent::new(0, ProviderStreamEventKind::Usage { usage }).unwrap();
        record_usage(Some(&sink), "qwen-token-plan-individual", 1, &[event]);
        let identity = QuotaIdentity::new("qwen-token-plan-individual", 1).unwrap();
        let state = store.state(&identity).unwrap().unwrap();
        assert_eq!(state.local_usage().input_tokens(), 4);
        assert_eq!(state.local_usage().output_tokens(), 3);
    }
}
