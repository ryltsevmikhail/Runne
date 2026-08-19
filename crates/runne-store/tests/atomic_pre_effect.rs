use std::sync::{Arc, Barrier};

use runne_application::security::atomic_transaction::{
    AtomicPreEffectTransaction, AtomicTransactionError, AuthorizationDecision, IntentStatus,
    PreEffectTransactionOutcome,
};
use runne_store::atomic_pre_effect::SqliteAtomicPreEffectStore;

#[path = "support/validated_reopen.rs"]
mod validated_reopen;

struct TestDatabase {
    database: validated_reopen::ValidatedTestDatabase,
    identity: validated_reopen::MainDatabaseIdentity,
}

impl TestDatabase {
    fn new(name: &str) -> Self {
        let database = validated_reopen::ValidatedTestDatabase::new(name);
        let identity = validated_reopen::initialize_database_identity(database.path()).unwrap();
        Self { database, identity }
    }

    fn path(&self) -> &str {
        self.database.path()
    }

    fn adopt(&self) -> SqliteAtomicPreEffectStore {
        let connection =
            validated_reopen::open_validated_connection(self.path(), self.identity).unwrap();
        SqliteAtomicPreEffectStore::open_with_connection(self.path(), connection).unwrap()
    }
}

fn fresh_store(name: &str) -> (TestDatabase, SqliteAtomicPreEffectStore) {
    let database = TestDatabase::new(name);
    let store = SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).unwrap();
    (database, store)
}

fn valid_tx(intent_id: &str, permit_id: &str) -> AtomicPreEffectTransaction {
    AtomicPreEffectTransaction {
        authorization_decision: AuthorizationDecision {
            grant_id: "grant-1".into(),
            allowed: true,
            reason: "authorized".into(),
        },
        budget_reservation_id: format!("reservation-{intent_id}"),
        budget_amount: 1,
        side_effect_started: true,
        dispatch_intent: intent_id.into(),
        permit_id: permit_id.into(),
    }
}

#[test]
fn committed_pre_effect_survives_reopen_as_uncertain() {
    let (database, store) = fresh_store("reopen");
    let outcome = store
        .commit_pre_effect(&valid_tx("intent-1", "permit-1"))
        .unwrap();
    assert!(matches!(
        outcome,
        PreEffectTransactionOutcome::Committed { ref intent_id } if intent_id == "intent-1"
    ));
    drop(store);

    let reopened = SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).unwrap();
    let recovered = reopened.get_dispatch_intent("intent-1").unwrap().unwrap();

    assert_eq!(recovered.status, IntentStatus::Uncertain);
    assert_eq!(reopened.committed_count().unwrap(), 1);
}

#[test]
fn budget_failure_rolls_back_all_pre_effect_rows() {
    let (_path, store) = fresh_store("budget-rollback");
    let mut tx = valid_tx("intent-2", "permit-2");
    tx.budget_amount = 0;

    let result = store.commit_pre_effect(&tx);

    assert!(matches!(
        result,
        Err(AtomicTransactionError::BudgetUnavailable)
    ));
    assert_eq!(store.committed_count().unwrap(), 0);
    assert!(!store.permit_is_claimed("permit-2").unwrap());
    assert!(store.get_dispatch_intent("intent-2").unwrap().is_none());
}

#[test]
fn unbound_grant_or_budget_reservation_is_rejected_without_mutation() {
    let (_path, store) = fresh_store("binding-validation");
    let mut missing_grant = valid_tx("intent-binding-grant", "permit-binding-grant");
    missing_grant.authorization_decision.grant_id.clear();

    assert!(matches!(
        store.commit_pre_effect(&missing_grant),
        Err(AtomicTransactionError::IncompleteTransaction)
    ));

    let mut missing_reservation =
        valid_tx("intent-binding-reservation", "permit-binding-reservation");
    missing_reservation.budget_reservation_id.clear();

    assert!(matches!(
        store.commit_pre_effect(&missing_reservation),
        Err(AtomicTransactionError::BudgetUnavailable)
    ));
    assert_eq!(store.committed_count().unwrap(), 0);
}

#[test]
fn same_permit_for_different_intent_is_rejected_without_mutation() {
    let (_path, store) = fresh_store("permit-conflict");
    store
        .commit_pre_effect(&valid_tx("intent-3a", "permit-3"))
        .unwrap();

    let result = store.commit_pre_effect(&valid_tx("intent-3b", "permit-3"));

    assert!(matches!(
        result,
        Err(AtomicTransactionError::PermitIntentConflict)
    ));
    assert_eq!(store.committed_count().unwrap(), 1);
    assert!(store.get_dispatch_intent("intent-3b").unwrap().is_none());
}

#[test]
fn changed_exact_replay_is_rejected_without_mutation() {
    let (_path, store) = fresh_store("replay-conflict");
    let original = valid_tx("intent-4", "permit-4");
    store.commit_pre_effect(&original).unwrap();
    let mut changed = original;
    changed.authorization_decision.reason = "changed".into();

    let result = store.commit_pre_effect(&changed);

    assert!(matches!(
        result,
        Err(AtomicTransactionError::ReplayConflict)
    ));
    assert_eq!(store.committed_count().unwrap(), 1);
}

#[test]
fn audit_write_failure_rolls_back_every_pre_effect_row() {
    let (database, store) = fresh_store("audit-rollback");
    validated_reopen::open_validated_connection(database.path(), database.identity)
        .unwrap()
        .execute_batch(
            "CREATE TRIGGER fail_security_audit_insert
             BEFORE INSERT ON security_audit_pre_effect
             BEGIN
                 SELECT RAISE(ABORT, 'injected audit failure');
             END;",
        )
        .unwrap();

    let result = store.commit_pre_effect(&valid_tx("intent-5", "permit-5"));

    assert!(matches!(
        result,
        Err(AtomicTransactionError::StoreUnavailable)
    ));
    assert_eq!(store.committed_count().unwrap(), 0);
    assert!(!store.permit_is_claimed("permit-5").unwrap());
    assert!(store.get_dispatch_intent("intent-5").unwrap().is_none());
}

#[test]
fn concurrent_connections_claim_one_permit_for_exactly_one_intent() {
    let (database, first_store) = fresh_store("concurrent-permit");
    assert!(SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).is_err());
    let second_store = database.adopt();
    let barrier = Arc::new(Barrier::new(2));
    let first_barrier = barrier.clone();
    let first = std::thread::spawn(move || {
        first_barrier.wait();
        first_store.commit_pre_effect(&valid_tx("intent-6a", "permit-6"))
    });
    let second_barrier = barrier.clone();
    let second = std::thread::spawn(move || {
        second_barrier.wait();
        second_store.commit_pre_effect(&valid_tx("intent-6b", "permit-6"))
    });

    let outcomes = [first.join().unwrap(), second.join().unwrap()];

    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|result| matches!(result, Err(AtomicTransactionError::PermitIntentConflict)))
            .count(),
        1
    );
    let reopened = SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).unwrap();
    assert_eq!(reopened.committed_count().unwrap(), 1);
}

#[test]
fn incomplete_durable_pre_effect_fails_closed_on_recovery() {
    let (database, store) = fresh_store("corrupt-recovery");
    store
        .commit_pre_effect(&valid_tx("intent-7", "permit-7"))
        .unwrap();
    drop(store);
    let raw =
        validated_reopen::open_validated_connection(database.path(), database.identity).unwrap();
    raw.execute(
        "DELETE FROM security_authorization_decisions WHERE intent_id = 'intent-7'",
        [],
    )
    .unwrap();
    drop(raw);

    let reopened = SqliteAtomicPreEffectStore::open(std::path::Path::new(database.path())).unwrap();

    assert!(matches!(
        reopened.get_dispatch_intent("intent-7"),
        Err(AtomicTransactionError::CorruptData)
    ));
}

#[test]
fn recovery_counts_components_per_intent() {
    let (_path, store) = fresh_store("recovery-components-per-intent");
    store
        .commit_pre_effect(&valid_tx("intent-8a", "permit-8a"))
        .unwrap();
    store
        .commit_pre_effect(&valid_tx("intent-8b", "permit-8b"))
        .unwrap();

    for intent_id in ["intent-8a", "intent-8b"] {
        let recovered = store.get_dispatch_intent(intent_id).unwrap().unwrap();
        assert_eq!(recovered.intent_id, intent_id);
        assert_eq!(recovered.status, IntentStatus::Uncertain);
    }
}
