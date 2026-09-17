use super::{
    Arc, ProviderStreamEvent, ProviderStreamEventKind, QuotaEvidenceSink, QuotaIdentity,
    SubscriptionBudgetAuthority, SystemTime, UNIX_EPOCH,
};

pub fn spend_budget(
    budget: Option<&Arc<dyn SubscriptionBudgetAuthority>>,
    provider_id: &str,
    version: u64,
    events: &[ProviderStreamEvent],
) {
    let Some(budget) = budget else { return };
    let tokens: u64 = events
        .iter()
        .filter_map(|event| match event.kind() {
            ProviderStreamEventKind::Usage { usage } => {
                usage.input_tokens().checked_add(usage.output_tokens())
            }
            _ => None,
        })
        .sum();
    let _ = budget.spend(provider_id, version, tokens);
}

pub fn record_usage(
    provider_id: &str,
    credential_version: u64,
    sink: Option<&Arc<dyn QuotaEvidenceSink>>,
    events: &[ProviderStreamEvent],
) {
    let Some(sink) = sink else { return };
    let Ok(identity) = QuotaIdentity::new(provider_id, credential_version) else {
        return;
    };
    let observed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(1, |duration| duration.as_secs().max(1));
    for event in events {
        if let ProviderStreamEventKind::Usage { usage } = event.kind() {
            let _ = sink.record_usage(
                &identity,
                usage.input_tokens(),
                usage.output_tokens(),
                observed,
            );
        }
    }
}
