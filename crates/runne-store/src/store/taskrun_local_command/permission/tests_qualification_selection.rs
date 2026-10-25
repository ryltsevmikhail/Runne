//! Shared terminal classifier/exact-selection CAS MODEL, not a concrete terminal UoW.
use super::super::{capture::verify_current_selection, retained_policy};
use super::{mode, support::Case};
use runne_application::{permission_modes::PermissionMode, ports::EventStoreError};

fn selection_race(next: PermissionMode) {
    let c = Case::new(true);
    let lease = c.lease();
    let preliminary = {
        let mut writer = c.f.store.inner.writer.lock().unwrap();
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        let result =
            retained_policy::assess_binding(&tx, &c.f.store, &c.b, lease.as_ref()).unwrap();
        verify_current_selection(
            &tx,
            &c.b.selection().scope,
            &result.selection,
            c.f.trust_id(),
        )
        .unwrap();
        result
    };
    assert_eq!(preliminary.stop, None);
    // Lawful sequential SAME borrowed lease model, not an independent writer inside that lease.
    if next == PermissionMode::RiskBased {
        mode::commit(&c.f, next, 1, lease.as_ref());
    } else {
        mode::commit_expiring(&c.f, next, 1, lease.as_ref());
    }
    let authoritative = {
        let mut writer = c.f.store.inner.writer.lock().unwrap();
        let tx = writer
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        // Exact production guard used by terminal_validate BEFORE it recomputes classification.
        assert_eq!(
            verify_current_selection(
                &tx,
                &c.b.selection().scope,
                &preliminary.selection,
                c.f.trust_id()
            ),
            Err(EventStoreError::CorruptData)
        );
        let result =
            retained_policy::assess_binding(&tx, &c.f.store, &c.b, lease.as_ref()).unwrap();
        verify_current_selection(
            &tx,
            &c.b.selection().scope,
            &result.selection,
            c.f.trust_id(),
        )
        .unwrap();
        result
    };
    assert_ne!(authoritative.selection, preliminary.selection);
    assert_eq!(
        authoritative.stop,
        if next == PermissionMode::RiskBased {
            None
        } else {
            Some(2)
        }
    );
    drop(lease);
    // Public monitor entry must acquire its own genuine current lease outside the borrowed one.
    assert_eq!(
        c.f.store
            .observe_local_command_permission_policy(&c.b)
            .unwrap(),
        authoritative.stop
    );
    assert_eq!(c.spent_on_owned_reopen(), 0);
}

#[test]
fn compatible_refresh_still_rejects_stale_terminal_preliminary_selection() {
    selection_race(PermissionMode::RiskBased);
}

#[test]
fn incompatible_refresh_rejects_stale_choice_and_monitor_matches_shared_classifier() {
    selection_race(PermissionMode::AskAlways);
}
