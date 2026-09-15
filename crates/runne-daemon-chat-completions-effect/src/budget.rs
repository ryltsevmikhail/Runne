use super::*;

pub(super) fn spend_budget(
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
