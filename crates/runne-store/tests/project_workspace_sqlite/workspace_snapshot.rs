use std::sync::mpsc;
use std::time::Duration;

use runne_application::ports::ProjectWorkspaceRepository;
use runne_domain::id::WorkspaceId;

use super::support::*;

#[test]
fn workspace_snapshot_holds_the_writer_boundary_during_operation() {
    let database = Database::new("project-workspace-snapshot-boundary");
    let repository = database.repository();
    create_project(&repository);
    create_workspace(&repository);
    let (start_tx, start_rx) = mpsc::channel();
    let (done_tx, done_rx) = mpsc::channel();
    let mutator = repository.clone();
    let worker = std::thread::spawn(move || {
        start_rx.recv().expect("snapshot started");
        let result = mutator.open_workspace(
            "owner",
            command(3),
            &key("open-workspace"),
            WorkspaceId::from_bytes(WORKSPACE),
            1,
        );
        done_tx.send(result).expect("mutation result receiver");
    });

    let version = repository
        .with_current_workspace_version("owner", WorkspaceId::from_bytes(WORKSPACE), |version| {
            start_tx.send(()).expect("mutation start receiver");
            assert!(done_rx.recv_timeout(Duration::from_millis(50)).is_err());
            Ok(version)
        })
        .expect("workspace snapshot");
    assert_eq!(version, 1);
    worker.join().expect("mutation worker");
    assert_eq!(
        done_rx
            .recv()
            .expect("mutation")
            .expect("mutation")
            .version(),
        2
    );
}
