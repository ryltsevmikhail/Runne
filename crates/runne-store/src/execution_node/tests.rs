use super::*;
use crate::schema::{
    apply_migrations, apply_migrations_through_v40_for_test, generate_authority_id,
    next_launch_generation,
};

#[test]
fn v40_upgrade_registry_restart_and_expiry_are_fail_closed() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("registry.sqlite");
    let connection = Connection::open(&path).unwrap();
    apply_migrations_through_v40_for_test(&connection).unwrap();
    let node_id = generate_authority_id();
    crate::schema::ensure_authority_id(&connection, &node_id).unwrap();
    let first_epoch = next_launch_generation(&connection).unwrap();
    apply_migrations(&connection).unwrap();

    let descriptor = LinuxNodeDescriptor { capacity: 2 };
    register_local_linux_node(&connection, node_id, first_epoch, descriptor, 30).unwrap();
    register_local_linux_node(&connection, node_id, first_epoch, descriptor, 30).unwrap();
    assert_eq!(
        eligible_local_linux_node(&connection)
            .unwrap()
            .unwrap()
            .descriptor,
        descriptor
    );
    heartbeat_local_linux_node(&connection, node_id, first_epoch, 30).unwrap();
    connection
        .execute_batch("UPDATE execution_nodes SET heartbeat_at_ms=1, expires_at_ms=2;")
        .unwrap();
    assert!(eligible_local_linux_node(&connection).unwrap().is_none());
    assert_stale(heartbeat_local_linux_node(
        &connection,
        node_id,
        first_epoch,
        30,
    ));
    assert_stale(register_local_linux_node(
        &connection,
        node_id,
        first_epoch,
        descriptor,
        30,
    ));
    drop(connection);

    let connection = Connection::open(&path).unwrap();
    let second_epoch = next_launch_generation(&connection).unwrap();
    assert_eq!(second_epoch, first_epoch + 1);
    assert_eq!(eligible_local_linux_node(&connection).unwrap(), None);
    assert_stale(register_local_linux_node(
        &connection,
        node_id,
        first_epoch,
        descriptor,
        30,
    ));
    assert_stale(heartbeat_local_linux_node(
        &connection,
        node_id,
        first_epoch,
        30,
    ));
    register_local_linux_node(&connection, node_id, second_epoch, descriptor, 30).unwrap();
    connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE execution_nodes SET heartbeat_at_ms=20, expires_at_ms=10;").unwrap();
    assert_corrupt(eligible_local_linux_node(&connection));
    assert_corrupt(heartbeat_local_linux_node(
        &connection,
        node_id,
        second_epoch,
        30,
    ));
    assert_corrupt(register_local_linux_node(
        &connection,
        node_id,
        second_epoch,
        descriptor,
        30,
    ));
    connection.execute_batch("UPDATE execution_nodes SET heartbeat_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)+10000, expires_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)+20000;").unwrap();
    assert_corrupt(eligible_local_linux_node(&connection));
    assert_corrupt(heartbeat_local_linux_node(
        &connection,
        node_id,
        second_epoch,
        30,
    ));
    connection.execute_batch("UPDATE execution_nodes SET heartbeat_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER), expires_at_ms=CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)+300001;").unwrap();
    assert_corrupt(eligible_local_linux_node(&connection));
    assert_corrupt(register_local_linux_node(
        &connection,
        node_id,
        second_epoch,
        descriptor,
        30,
    ));
    connection
        .execute_batch(
            "UPDATE execution_nodes SET heartbeat_at_ms=1,expires_at_ms=2,capacity=4294967296;",
        )
        .unwrap();
    assert_corrupt(eligible_local_linux_node(&connection));
}

#[test]
fn new_epoch_registration_rejects_corrupt_old_row() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let path = directory.path().join("corrupt-old-node.sqlite");
    let connection = Connection::open(path).unwrap();
    apply_migrations(&connection).unwrap();
    let node_id = generate_authority_id();
    crate::schema::ensure_authority_id(&connection, &node_id).unwrap();
    let first_epoch = next_launch_generation(&connection).unwrap();
    let descriptor = LinuxNodeDescriptor { capacity: 2 };
    register_local_linux_node(&connection, node_id, first_epoch, descriptor, 30).unwrap();
    connection.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE execution_nodes SET expires_at_ms=heartbeat_at_ms+300001;").unwrap();

    let second_epoch = next_launch_generation(&connection).unwrap();
    assert_corrupt(register_local_linux_node(
        &connection,
        node_id,
        second_epoch,
        descriptor,
        30,
    ));
}

fn assert_stale<T>(result: Result<T, NodeRegistryError>) {
    assert!(matches!(result, Err(NodeRegistryError::StaleEpoch)));
}

fn assert_corrupt<T>(result: Result<T, NodeRegistryError>) {
    assert!(matches!(result, Err(NodeRegistryError::Storage)));
}
