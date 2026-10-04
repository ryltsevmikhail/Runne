use super::*;
use runne_store::execution_node::LinuxNodeDescriptor;

#[test]
fn recovery_heartbeat_requires_exact_session_and_current_registered_epoch() {
    let (_directory, path, store, authority, generation) = store_fixture();
    let daemon = *uuid::Uuid::now_v7().as_bytes();
    let binding = test_binding(authority, daemon, generation, generation);
    store
        .register_local_linux_node(
            authority,
            generation,
            LinuxNodeDescriptor { capacity: 1 },
            30,
        )
        .unwrap();
    let sessions = protected_sessions(binding, store.clone());

    let before = node_generation_and_expiry(&path, authority);
    std::thread::sleep(std::time::Duration::from_millis(2));
    super::super::heartbeat_recovery_lease(
        &store, &sessions, authority, authority, daemon, generation,
    )
    .expect("exact current session renews registered node");
    let renewed = node_generation_and_expiry(&path, authority);
    assert_eq!(renewed.0, generation);
    assert!(renewed.1 > before.1);

    let wrong_session = [0x42; 16];
    let expiry = node_generation_and_expiry(&path, authority).1;
    assert!(
        super::super::heartbeat_recovery_lease(
            &store,
            &sessions,
            authority,
            wrong_session,
            daemon,
            generation,
        )
        .is_err()
    );
    assert!(
        super::super::heartbeat_recovery_lease(
            &store,
            &sessions,
            authority,
            authority,
            *uuid::Uuid::now_v7().as_bytes(),
            generation,
        )
        .is_err()
    );
    assert!(
        super::super::heartbeat_recovery_lease(
            &store,
            &sessions,
            authority,
            authority,
            daemon,
            generation + 1,
        )
        .is_err()
    );
    assert_eq!(node_generation_and_expiry(&path, authority).1, expiry);

    let connection = rusqlite::Connection::open(&path).unwrap();
    let next = next_launch_generation(&connection).unwrap();
    drop(connection);
    store
        .register_local_linux_node(authority, next, LinuxNodeDescriptor { capacity: 1 }, 30)
        .unwrap();
    let superseded = node_generation_and_expiry(&path, authority);
    assert!(
        super::super::heartbeat_recovery_lease(
            &store, &sessions, authority, authority, daemon, generation,
        )
        .is_err()
    );
    assert_eq!(node_generation_and_expiry(&path, authority), superseded);
}
