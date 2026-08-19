use std::collections::HashMap;

pub use runne_application::security::atomic_transaction::{
    AtomicPreEffectTransaction, AtomicTransactionError, AuthorizationDecision,
    PreEffectTransactionOutcome,
};

/// Хранилище атомарных транзакций в памяти для тестирования.
/// В production это была бы одна SQLite-транзакция BEGIN IMMEDIATE.
pub struct AtomicTransactionStore {
    transactions: HashMap<String, AtomicPreEffectTransaction>,
    permit_claims: HashMap<String, String>,
}

impl Default for AtomicTransactionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicTransactionStore {
    pub fn new() -> Self {
        Self {
            transactions: HashMap::new(),
            permit_claims: HashMap::new(),
        }
    }

    /// Фиксирует данные целиком или отменяет операцию.
    pub fn commit_pre_effect(
        &mut self,
        tx: AtomicPreEffectTransaction,
    ) -> Result<PreEffectTransactionOutcome, AtomicTransactionError> {
        let intent_id = tx.dispatch_intent.clone();

        // Проверяем все поля до фиксации.
        if !tx.authorization_decision.allowed {
            return Ok(PreEffectTransactionOutcome::RolledBack {
                reason: "authorization denied".into(),
            });
        }
        if tx.budget_reservation_id.is_empty() || tx.budget_amount == 0 {
            return Err(AtomicTransactionError::BudgetUnavailable);
        }
        if !tx.side_effect_started
            || tx.permit_id.is_empty()
            || intent_id.is_empty()
            || tx.authorization_decision.grant_id.is_empty()
            || tx.authorization_decision.reason.is_empty()
        {
            return Err(AtomicTransactionError::IncompleteTransaction);
        }
        if let Some(claimed_intent) = self.permit_claims.get(&tx.permit_id) {
            if claimed_intent == &intent_id {
                if self.transactions.get(&intent_id) != Some(&tx) {
                    return Err(AtomicTransactionError::ReplayConflict);
                }
                return Ok(PreEffectTransactionOutcome::Committed { intent_id });
            }
            return Err(AtomicTransactionError::PermitIntentConflict);
        }

        // Сохраняем транзакцию только после успешного прохождения всех проверок.
        self.permit_claims
            .insert(tx.permit_id.clone(), intent_id.clone());
        self.transactions.insert(intent_id.clone(), tx);
        Ok(PreEffectTransactionOutcome::Committed { intent_id })
    }

    pub fn get_intent(&self, intent_id: &str) -> Option<&AtomicPreEffectTransaction> {
        self.transactions.get(intent_id)
    }

    pub fn is_committed(&self, intent_id: &str) -> bool {
        self.transactions.contains_key(intent_id)
    }

    pub fn committed_count(&self) -> usize {
        self.transactions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_all_or_nothing_commit() {
        let mut store = AtomicTransactionStore::new();
        let tx = valid_tx("intent-1");

        let outcome = store.commit_pre_effect(tx).unwrap();

        assert!(matches!(
            outcome,
            PreEffectTransactionOutcome::Committed { .. }
        ));
        assert!(store.is_committed("intent-1"));
    }

    #[test]
    fn budget_failure_rolls_back() {
        let mut store = AtomicTransactionStore::new();
        let mut tx = valid_tx("intent-2");
        tx.budget_amount = 0;

        let result = store.commit_pre_effect(tx);

        assert!(matches!(
            result,
            Err(AtomicTransactionError::BudgetUnavailable)
        ));
        assert!(!store.is_committed("intent-2"));
    }

    #[test]
    fn exact_replay_of_claimed_permit_is_idempotent() {
        let mut store = AtomicTransactionStore::new();
        let tx = valid_tx("intent-3");

        store.commit_pre_effect(tx.clone()).unwrap();
        let result = store.commit_pre_effect(tx);

        assert!(matches!(
            result,
            Ok(PreEffectTransactionOutcome::Committed { .. })
        ));
        assert_eq!(store.committed_count(), 1);
    }

    #[test]
    fn authorization_denied_rolls_back() {
        let mut store = AtomicTransactionStore::new();
        let mut tx = valid_tx("intent-4");
        tx.authorization_decision = AuthorizationDecision {
            grant_id: "g1".into(),
            allowed: false,
            reason: "denied".into(),
        };

        let outcome = store.commit_pre_effect(tx).unwrap();

        assert!(matches!(
            outcome,
            PreEffectTransactionOutcome::RolledBack { .. }
        ));
        assert!(!store.is_committed("intent-4"));
    }

    #[test]
    fn committed_intent_is_visible_in_the_same_in_memory_store() {
        let mut store = AtomicTransactionStore::new();
        store.commit_pre_effect(valid_tx("intent-5")).unwrap();

        assert!(store.is_committed("intent-5"));
        assert!(store.get_intent("intent-5").is_some());
    }

    #[test]
    fn exact_replay_of_claimed_permit_returns_prior_outcome_without_second_commit() {
        let mut store = AtomicTransactionStore::new();
        let tx = valid_tx_with_permit("intent-6", "permit-1");
        let first = store.commit_pre_effect(tx.clone()).unwrap();

        let replay = store.commit_pre_effect(tx).unwrap();

        assert_eq!(first.intent_id(), replay.intent_id());
        assert_eq!(store.committed_count(), 1);
    }

    #[test]
    fn same_permit_with_different_intent_is_rejected_without_mutation() {
        let mut store = AtomicTransactionStore::new();
        store
            .commit_pre_effect(valid_tx_with_permit("intent-7a", "permit-2"))
            .unwrap();

        let result = store.commit_pre_effect(valid_tx_with_permit("intent-7b", "permit-2"));

        assert!(matches!(
            result,
            Err(AtomicTransactionError::PermitIntentConflict)
        ));
        assert_eq!(store.committed_count(), 1);
        assert!(store.get_intent("intent-7b").is_none());
    }

    #[test]
    fn same_permit_and_intent_with_changed_payload_is_rejected_without_mutation() {
        let mut store = AtomicTransactionStore::new();
        let original = valid_tx_with_permit("intent-8", "permit-3");
        store.commit_pre_effect(original.clone()).unwrap();
        let mut changed = original.clone();
        changed.authorization_decision.reason = "changed".into();

        let result = store.commit_pre_effect(changed);

        assert!(matches!(
            result,
            Err(AtomicTransactionError::ReplayConflict)
        ));
        assert_eq!(store.get_intent("intent-8"), Some(&original));
        assert_eq!(store.committed_count(), 1);
    }

    #[test]
    fn incomplete_pre_effect_marker_is_rejected_without_mutation() {
        let mut store = AtomicTransactionStore::new();
        let mut tx = valid_tx("intent-9");
        tx.side_effect_started = false;

        let result = store.commit_pre_effect(tx);

        assert!(matches!(
            result,
            Err(AtomicTransactionError::IncompleteTransaction)
        ));
        assert_eq!(store.committed_count(), 0);
    }

    fn valid_tx(intent: &str) -> AtomicPreEffectTransaction {
        valid_tx_with_permit(intent, &format!("permit-{intent}"))
    }

    fn valid_tx_with_permit(intent: &str, permit_id: &str) -> AtomicPreEffectTransaction {
        AtomicPreEffectTransaction {
            authorization_decision: AuthorizationDecision {
                grant_id: "g1".into(),
                allowed: true,
                reason: "ok".into(),
            },
            budget_reservation_id: format!("reservation-{intent}"),
            budget_amount: 1,
            side_effect_started: true,
            dispatch_intent: intent.into(),
            permit_id: permit_id.into(),
        }
    }
}
