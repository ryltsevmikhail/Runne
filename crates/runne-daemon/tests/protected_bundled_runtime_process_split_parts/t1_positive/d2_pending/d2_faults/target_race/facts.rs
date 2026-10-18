use std::{fs::File, os::unix::fs::FileExt, path::Path};

use super::canary_watch::{FileIdentity, drain_canary_events, file_identity};
use super::*;

pub(super) const BARRIER_DIRECTORY: &str = ".runne-test-approved-target-race";
pub(super) const TARGET_NAME: &str = "fixture-created.txt";

#[derive(Debug, PartialEq, Eq)]
pub(super) struct PermissionRefs {
    pub(super) attempt_id: Vec<u8>,
    pub(super) approval_id: Vec<u8>,
    pub(super) approval_digest: Vec<u8>,
    pub(super) policy_revision: i64,
    pub(super) workspace_id: Vec<u8>,
    pub(super) selected_mode: i64,
    pub(super) authorization_revision: i64,
    pub(super) managed_policy_version: i64,
    pub(super) managed_policy_digest: Vec<u8>,
    pub(super) decision_source: i64,
    pub(super) relevant_policy_digest: Vec<u8>,
}

pub(super) fn assert_failure_counts(
    database: &Path,
    runtime_root: &Path,
    task: runne_runtime_client::CanonicalId,
) {
    database::assert_failure_projection(database, task);
    assert_eq!(database::invocation_count(database, task), 1);
    assert_eq!(database::invocation_state(database, task), "audit_only");
    assert_eq!(database::result_count(database, task), 0);
    assert_eq!(database::release_intent_count(database, task), 1);
    assert_eq!(database::managed_area_launch_count(database, task), 1);
    assert_eq!(database::local_stop_state(database, task), Some(2));
    let task_id = id_bytes(task);
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open read-only no-result race view");
    let (has_result_bytes, has_result_digest, has_encrypted_receipt): (bool, bool, bool) =
        connection
            .query_row(
                "SELECT result_bytes IS NOT NULL,result_digest IS NOT NULL,
                    helper_receipt_bytes IS NOT NULL AND receipt_nonce IS NOT NULL
             FROM taskrun_tool_invocations WHERE taskrun_id=?1",
                [task_id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("read exact invocation result projection");
    assert!(!has_result_bytes, "no plaintext tool result was released");
    assert!(has_result_digest, "audit-only result digest is retained");
    assert!(has_encrypted_receipt, "encrypted audit receipt is retained");
    assert_eq!(
        fixture_count(runtime_root, "fixture-provider-request-count"),
        1
    );
}

pub(super) fn permission_refs(
    database: &Path,
    task: runne_runtime_client::CanonicalId,
) -> PermissionRefs {
    let task_id = id_bytes(task);
    let connection =
        rusqlite::Connection::open_with_flags(database, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .expect("open permission race read-only view");
    connection
        .query_row(
            "SELECT i.attempt_id,i.approval_id,i.approval_digest,i.policy_revision,
                    p.workspace_id,p.selected_mode,p.authorization_revision,
                    p.managed_policy_version,p.managed_policy_digest,p.decision_source,
                    p.relevant_policy_digest
             FROM taskrun_tool_invocations i
             JOIN taskrun_tool_permission_admissions p
               USING(taskrun_id,attempt_id,cycle_id,proposal_index)
             WHERE i.taskrun_id=?1 AND i.tool_name='workspace.file.create_new'",
            [task_id.as_slice()],
            |row| {
                Ok(PermissionRefs {
                    attempt_id: row.get(0)?,
                    approval_id: row.get(1)?,
                    approval_digest: row.get(2)?,
                    policy_revision: row.get(3)?,
                    workspace_id: row.get(4)?,
                    selected_mode: row.get(5)?,
                    authorization_revision: row.get(6)?,
                    managed_policy_version: row.get(7)?,
                    managed_policy_digest: row.get(8)?,
                    decision_source: row.get(9)?,
                    relevant_policy_digest: row.get(10)?,
                })
            },
        )
        .expect("read exact create approval and grant bindings")
}

pub(super) fn assert_public_projection_excludes(
    snapshot: &runne_runtime_client::TaskRunSnapshot,
    canary: &str,
) {
    assert!(
        !format!("{snapshot:?}").contains(canary),
        "outside canary is absent from the public TaskRun projection"
    );
}

pub(super) fn assert_canary_unchanged(
    canary_watch: &File,
    held_file: &File,
    path: &Path,
    before: &FileIdentity,
    expected: &[u8],
) {
    assert_eq!(
        file_identity(&std::fs::symlink_metadata(path).expect("canary metadata")),
        *before
    );
    assert_eq!(drain_canary_events(canary_watch), (0, 0, 0));
    let mut observed = vec![0_u8; expected.len()];
    let count = held_file
        .read_at(&mut observed, 0)
        .expect("read held canary inode");
    assert!(
        count == expected.len(),
        "outside canary length stayed unchanged"
    );
    assert!(
        observed == expected,
        "outside canary bytes stayed unchanged"
    );
    assert_eq!(
        drain_canary_events(canary_watch),
        (0, 1, 0),
        "only the fixture's held-fd verification read accessed the canary"
    );
}

pub(super) fn id_bytes(id: runne_runtime_client::CanonicalId) -> Vec<u8> {
    uuid::Uuid::parse_str(&id.to_string())
        .expect("canonical race fixture id")
        .as_bytes()
        .to_vec()
}

pub(super) fn mode_number(mode: runne_api::PermissionModeV1) -> i64 {
    match mode {
        runne_api::PermissionModeV1::AskAlways => 1,
        runne_api::PermissionModeV1::RiskBased => 2,
        runne_api::PermissionModeV1::FullAccess => 3,
    }
}
