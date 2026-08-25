use super::*;
use runne_application::ports::RuntimeAuthorityId;
use runne_security::SecretBroker;
use std::sync::Arc;
use tempfile::TempDir;

fn store() -> (TempDir, StoreTransaction) {
    let directory = TempDir::new().expect("temporary root");
    let daemon = directory.path().join("runne-daemon");
    std::fs::create_dir(&daemon).expect("daemon directory");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root permissions");
        std::fs::set_permissions(&daemon, std::fs::Permissions::from_mode(0o700))
            .expect("daemon permissions");
    }
    let database = daemon.join("event-log.sqlite");
    let store = StoreTransaction::open(
        &database.to_string_lossy(),
        RuntimeAuthorityId("process-store-test".into()),
        Arc::new(SecretBroker::new().prohibited_content_guard()),
    )
    .expect("store");
    (directory, store)
}

fn record() -> DurableProcessRecord {
    DurableProcessRecord {
        process_id: [1; 16],
        invocation_id: [2; 16],
        workspace_id: [3; 16],
        task_run_id: [4; 16],
        attempt_id: [5; 16],
        principal_id: "local-owner".into(),
        state: 2,
        version: 1,
        next_output_sequence: 1,
        request_digest: [6; 32],
        intent_digest: [14; 32],
        owner_id: [7; 16],
        binding_attempt_id: [8; 16],
        session_id: [9; 16],
        generation_id: [10; 16],
        tree_handle: [11; 16],
        pid: 42,
        start_identity: [12; 32],
        launch_nonce: [13; 16],
    }
}

#[test]
fn process_registry_and_sanitized_output_survive_reopen() {
    let (_directory, store) = store();
    let record = record();
    store.save_process_record(&record).expect("save record");
    store
        .append_process_output(&DurableProcessOutput {
            process_id: record.process_id,
            sequence: 1,
            stream: 1,
            text: "ready\n".into(),
        })
        .expect("save output");
    assert_eq!(store.load_process_records("local-owner").unwrap(), vec![record.clone()]);
    assert_eq!(
        store.load_process_output(record.process_id, 0).unwrap(),
        vec![DurableProcessOutput {
            process_id: record.process_id,
            sequence: 1,
            stream: 1,
            text: "ready\n".into(),
        }]
    );
    store
        .append_process_output(&DurableProcessOutput {
            process_id: record.process_id,
            sequence: 1,
            stream: 1,
            text: "ready\n".into(),
        })
        .expect("exact replay is idempotent");
    assert_eq!(
        store
        .append_process_output(&DurableProcessOutput {
            process_id: record.process_id,
            sequence: 1,
            stream: 2,
            text: "different".into(),
        })
        .unwrap_err(),
        ProcessStoreError::Conflict
    );
    let mut changed = record.clone();
    changed.invocation_id = [99; 16];
    assert_eq!(
        store.save_process_record(&changed),
        Err(ProcessStoreError::Conflict)
    );
    assert_eq!(store.load_process_output(record.process_id, 0).unwrap().len(), 1);
}
