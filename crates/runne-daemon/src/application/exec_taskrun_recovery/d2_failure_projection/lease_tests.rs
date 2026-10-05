use super::super::super::exec_taskrun_worker::provider_only_test_lease_heartbeat;
use runne_application::ports::ExecutionNodeId;
use runne_security::SecretBroker;
use runne_store::{
    execution_node::LinuxNodeDescriptor,
    schema::{
        ConnectionMode, apply_migrations, ensure_authority_id, next_launch_generation,
        open_managed_connection,
    },
    store::StoreTransaction,
};
use std::sync::Arc;

fn registered_store() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    StoreTransaction,
    [u8; 16],
    u64,
) {
    let directory = tempfile::tempdir().unwrap();
    let daemon_dir = directory.path().join("daemon");
    std::fs::create_dir(&daemon_dir).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&daemon_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = daemon_dir.join("store.sqlite");
    let connection = open_managed_connection(&path, ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let node = *uuid::Uuid::now_v7().as_bytes();
    ensure_authority_id(&connection, &node).unwrap();
    let epoch = next_launch_generation(&connection).unwrap();
    drop(connection);
    let store = StoreTransaction::open(
        path.to_str().unwrap(),
        runne_application::ports::RuntimeAuthorityId(hex::encode(node)),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .unwrap();
    store
        .register_local_linux_node(node, epoch, LinuxNodeDescriptor { capacity: 1 }, 300)
        .unwrap();
    (directory, path, store, node, epoch)
}

#[test]
fn provider_only_fixture_heartbeat_renews_only_the_live_exact_node_epoch() {
    let (_directory, path, store, node, epoch) = registered_store();
    let exact = provider_only_test_lease_heartbeat(
        store.clone(),
        ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
        epoch,
    );
    exact().unwrap();

    let wrong_node = provider_only_test_lease_heartbeat(
        store.clone(),
        ExecutionNodeId(uuid::Uuid::now_v7().to_string()),
        epoch,
    );
    assert!(wrong_node().is_err());
    let wrong_epoch = provider_only_test_lease_heartbeat(
        store.clone(),
        ExecutionNodeId(uuid::Uuid::from_bytes(node).to_string()),
        epoch + 1,
    );
    assert!(wrong_epoch().is_err());

    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE execution_nodes SET heartbeat_at_ms=1,expires_at_ms=2 WHERE node_id=?1",
            [node.as_slice()],
        )
        .unwrap();
    assert!(exact().is_err());
}
