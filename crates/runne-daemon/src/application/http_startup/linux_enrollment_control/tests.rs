use super::control_or_compose;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[test]
fn protected_without_provider_control_composes_once() {
    let calls = AtomicUsize::new(0);
    let selected = control_or_compose(true, None, || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, crate::error::DaemonError>(Arc::new("standalone"))
    })
    .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(
        selected
            .as_deref()
            .is_some_and(|value| *value == "standalone")
    );
}

#[test]
fn existing_provider_control_is_reused_without_composition() {
    let calls = AtomicUsize::new(0);
    let existing = Arc::new("provider");
    let selected = control_or_compose(true, Some(Arc::clone(&existing)), || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, crate::error::DaemonError>(Arc::new("standalone"))
    })
    .unwrap()
    .unwrap();
    assert!(Arc::ptr_eq(&selected, &existing));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn unprotected_startup_does_not_compose_a_control() {
    let calls = AtomicUsize::new(0);
    let selected = control_or_compose(false, None, || {
        calls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, crate::error::DaemonError>(Arc::new("standalone"))
    })
    .unwrap();
    assert!(selected.is_none());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}
