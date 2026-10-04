use super::*;

#[test]
fn node_reconciliation_rejects_replaced_authority_and_daemon_instances() {
    let (_directory, _path, store, authority, generation) = store_fixture();
    let daemon = *uuid::Uuid::now_v7().as_bytes();
    let sessions = protected_sessions(
        test_binding(authority, daemon, generation, 7),
        store.clone(),
    );
    let mut node = LinuxExecutionNode::new(authority, authority, [13; 16], generation);
    assert!(node.reconcile(&store, &sessions).is_err());

    let mut node = LinuxExecutionNode::new(authority, authority, daemon, generation);
    let replaced_authority = *uuid::Uuid::now_v7().as_bytes();
    let replaced_authority = protected_sessions(
        test_binding(replaced_authority, daemon, generation, 7),
        store.clone(),
    );
    assert!(node.reconcile(&store, &replaced_authority).is_err());
}

#[test]
fn node_reconciliation_keeps_database_and_session_authorities_distinct() {
    let (_directory, path, store, database_authority, generation) = store_fixture();
    let local_session_authority = *uuid::Uuid::now_v7().as_bytes();
    let daemon = *uuid::Uuid::now_v7().as_bytes();
    let sessions = protected_sessions(
        test_binding(local_session_authority, daemon, generation, 7),
        store.clone(),
    );
    let mut node = LinuxExecutionNode::new(
        database_authority,
        local_session_authority,
        daemon,
        generation,
    );

    node.register(&store, &sessions).unwrap();
    assert_eq!(
        node_generation_and_expiry(&path, database_authority).0,
        generation
    );
}

#[test]
fn consumed_pending_generation_is_not_a_valid_defer_window() {
    let (_directory, _path, store, authority, generation) = store_fixture();
    let daemon = *uuid::Uuid::now_v7().as_bytes();
    let binding = test_binding(authority, daemon, generation, 7);
    let pending_sessions = protected_sessions(binding.clone(), store.clone());
    let mut node = LinuxExecutionNode::new(authority, authority, daemon, generation);
    node.register(&store, &pending_sessions).unwrap();
    let reserved = pending_sessions
        .lock()
        .unwrap()
        .reserve_protected_enrollment_generation()
        .unwrap();

    let other_session = protected_sessions(binding.clone(), store.clone());
    let successor = test_binding(authority, daemon, reserved, 8);
    other_session
        .lock()
        .unwrap()
        .rotate_protected_enrollment_epoch(
            &binding,
            successor,
            [21; 32],
            Duration::from_secs(1),
            Duration::from_secs(30),
        )
        .unwrap();

    assert!(node.reconcile(&store, &pending_sessions).is_err());
    assert_eq!(node.launch_generation, generation);
}
