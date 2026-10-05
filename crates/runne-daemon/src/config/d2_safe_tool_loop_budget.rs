/// Explicit owner-private finite provider admission limits for the D2 tool profile.
/// Absence means the tool profile is unavailable and never receives an implicit budget.
#[derive(Debug, Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct D2SafeToolLoopBudgetConfig {
    token_budget_limit: u64,
    cost_budget_limit_micros: u64,
}

impl D2SafeToolLoopBudgetConfig {
    pub(crate) fn limits(&self) -> Option<(u64, u64)> {
        (self.token_budget_limit > 0
            && self.cost_budget_limit_micros > 0
            && self.token_budget_limit <= i64::MAX as u64
            && self.cost_budget_limit_micros <= i64::MAX as u64)
            .then_some((self.token_budget_limit, self.cost_budget_limit_micros))
    }
}
