#![allow(dead_code)]

use runne_domain::id::{ApprovalId, TaskRunId};
use runne_domain::task_run::TaskRunLocalCommand;
use runne_store::store::LocalCommandApprovalBinding;
use rusqlite::Connection;

use super::support::*;

#[path = "../support/x2_historical_schema_fixture/mod.rs"]
mod historical_schema;

mod legacy_migration;
mod seed;

pub struct PreparedLegacyLocalCommand {
    pub database: Database,
    pub taskrun_id: TaskRunId,
    pub local: TaskRunLocalCommand,
    pub approval_id: ApprovalId,
    pub binding: LocalCommandApprovalBinding,
}

pub use legacy_migration::migrate_pending;
pub use seed::{
    create_pending_approval, migration_rejects_fixture, prepare, prepare_with_node_authority,
};

#[tokio::test(flavor = "current_thread")]
async fn historical_denied_without_release_receipt_is_rejected() {
    assert!(
        migration_rejects_fixture(
            "legacy-denied-without-release",
            0xa1,
            0xa2,
            "denied",
            true,
            true
        )
        .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn historical_approval_pending_without_full_binding_is_rejected() {
    assert!(
        migration_rejects_fixture(
            "legacy-approval-missing-binding",
            0xa3,
            0xa4,
            "approval_pending",
            false,
            true,
        )
        .await
    );
}

#[tokio::test(flavor = "current_thread")]
async fn historical_local_command_without_submit_receipt_is_rejected() {
    assert!(
        migration_rejects_fixture(
            "legacy-approval-missing-origin",
            0xa5,
            0xa6,
            "approval_pending",
            true,
            false,
        )
        .await
    );
}

fn schema_version(connection: &Connection) -> i64 {
    connection
        .query_row("SELECT MAX(version) FROM schema_version", [], |row| {
            row.get(0)
        })
        .unwrap()
}
