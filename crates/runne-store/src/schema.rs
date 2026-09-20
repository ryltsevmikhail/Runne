//! Database schema — DDL, migrations, and startup PRAGMA gates.
//!
//! The schema consists of:
//! - `schema_version` — tracks applied migrations
//! - `event_log_state` — singleton row for global position counter
//! - `aggregate_streams` — per-aggregate stream metadata
//! - `events` — committed event rows
//! - `command_receipts` — idempotency receipt store

use rand::RngCore;
use rand::rngs::OsRng;
use runne_domain::id::{EventLogLineageId, validate_uuid_v7_bytes};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

use rusqlite::{
    Connection, DatabaseName, OpenFlags, OptionalExtension, Result as SqliteResult, Transaction,
    TransactionBehavior,
};
use sha2::{Digest, Sha256};
use std::io::Read;

/// Current schema version. Increment when adding new DDL migrations.
pub const CURRENT_SCHEMA_VERSION: i64 = 39;

/// Fail-closed reason returned before a file-backed database is made writable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SchemaOpenDiagnostic {
    ZeroByteDatabase,
    SidecarPresent,
    FileIdentityUncertain,
    UnsafePath,
}

impl fmt::Display for SchemaOpenDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ZeroByteDatabase => "ZeroByteDatabase",
            Self::SidecarPresent => "SidecarPresent",
            Self::FileIdentityUncertain => "FileIdentityUncertain",
            Self::UnsafePath => "UnsafePath",
        })
    }
}

impl std::error::Error for SchemaOpenDiagnostic {}

/// Fail-closed disposition for an explicitly requested V12-to-V11 rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SchemaRollbackError {
    #[error("schema rollback source is unsupported")]
    UnsupportedSchema,
    #[error("schema rollback snapshot is unavailable")]
    SnapshotUnavailable,
    #[error("schema rollback fence is closed")]
    RollbackClosed,
    #[error("schema rollback snapshot does not match")]
    SnapshotMismatch,
    #[error("schema rollback path is unsafe")]
    UnsafePath,
    #[error("schema rollback store is unavailable")]
    StoreUnavailable,
    #[error("schema rollback authority switch is unavailable")]
    AuthoritySwitchUnavailable,
}

fn diagnostic_error(diagnostic: SchemaOpenDiagnostic) -> rusqlite::Error {
    rusqlite::Error::ToSqlConversionFailure(Box::new(diagnostic))
}

include!("schema/admission_identity.rs");
include!("schema/admission_open.rs");
include!("schema/admission_recovery.rs");
include!("schema/admission_classification.rs");
include!("schema/migration_control.rs");
include!("schema/validation.rs");
include!("schema/provider_validation.rs");
include!("schema/v12_snapshot.rs");
include!("schema/v12_fence.rs");
include!("schema/v12_rollback.rs");
include!("schema/startup.rs");
include!("schema/connection_profile.rs");
include!("schema/scanner_recovery_sidecar.rs");
include!("schema/project_trust_sidecar.rs");
include!("schema/migrations/v1_v3.rs");
include!("schema/migrations/v4.rs");
include!("schema/migrations/v5_v6.rs");
include!("schema/migrations/v7_v8.rs");
include!("schema/migrations/v9.rs");
include!("schema/migrations/v10_v11.rs");
include!("schema/migrations/v12.rs");
include!("schema/migrations/v13.rs");
include!("schema/migrations/v16.rs");
include!("schema/migrations/v17_bootstrap_reservations.rs");
include!("schema/migrations/v21_process.rs");
include!("schema/migrations/v22_process_intent.rs");
include!("schema/migrations/v23_approvals.rs");
include!("schema/migrations/v24_provider_credential_online.rs");
include!("schema/provider_credential_v24_schema.rs");
include!("schema/migrations/v25_provider_credential_begin_expiry.rs");
include!("schema/provider_credential_v25_schema.rs");
include!("schema/migrations/v26_provider_online_effect_binding.rs");
include!("schema/provider_credential_v26_schema.rs");
include!("schema/migrations/v27_provider_credential_migration_provenance.rs");
include!("schema/provider_credential_v27_schema.rs");
include!("schema/migrations/v28_provider_credential_completion_receipt.rs");
include!("schema/provider_credential_v28_schema.rs");
include!("schema/migrations/v29_provider_credential_attachment.rs");
include!("schema/provider_credential_v29_schema.rs");
include!("schema/migrations/v30_provider_credential_verification_binding.rs");
include!("schema/provider_credential_v30_schema.rs");
include!("schema/migrations/v31_provider_credential_legacy_cutover.rs");
include!("schema/provider_credential_v31_schema.rs");
include!("schema/migrations/v32_provider_credential_legacy_cutover_atomic.rs");
include!("schema/provider_credential_v32_schema.rs");
include!("schema/migrations/v33_credential_cleanup_recovery.rs");
include!("schema/provider_credential_v33_schema.rs");
include!("schema/v33_recovery_triggers.rs");
include!("schema/migrations/v34_legacy_cleanup_completion.rs");
include!("schema/migrations/v35_provider_qualification_fence.rs");
include!("schema/provider_qualification_v35_schema.rs");
include!("schema/migrations/v37_subscription_accounting.rs");
include!("schema/migrations/v38_subscription_budgets.rs");
include!("schema/migrations/v39_taskrun_lineage_origin.rs");
mod project_workspace_backfill;
mod project_workspace_schema;
#[cfg(test)]
pub(crate) mod project_workspace_test_helpers;
#[cfg(test)]
pub(crate) use project_workspace_schema::restore_v18_project_workspace_receipt_for_test;
#[cfg(test)]
pub(crate) use project_workspace_test_helpers::restore_v18_taskrun_lineage_for_test;
pub(crate) mod provider_schema;
pub mod recovery_diagnosis;
mod replay_promotion_snapshot_schema;
mod replay_snapshot_schema;
include!("schema/open.rs");
include!("schema/authority_identity.rs");
include!("schema/authority_launch.rs");
include!("schema/replay.rs");

#[cfg(test)]
pub(crate) fn restore_v25_credential_triggers_for_test(
    connection: &Connection,
) -> SqliteResult<()> {
    let ticket_trigger = V24_TRIGGERS
        .iter()
        .find(|(name, _)| *name == "provider_credential_ticket_insert_issued")
        .expect("V24 ticket trigger exists")
        .1;
    connection.execute_batch(&v25_trigger(
        "provider_credential_ticket_insert_issued",
        ticket_trigger,
    ))?;
    let insert_trigger = V24_TRIGGERS
        .iter()
        .find(|(name, _)| *name == "provider_credential_operation_insert_prepared")
        .expect("V24 insert trigger exists")
        .1;
    connection.execute_batch(&v25_trigger(
        "provider_credential_operation_insert_prepared",
        insert_trigger,
    ))?;
    connection.execute_batch(v24_head_active_lifecycle_trigger())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::params;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt as _;

    const TEST_ID: [u8; 16] = [0x42; 16];

    fn initialize_v1(conn: &Connection) {
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL DEFAULT (datetime('now'))
            );",
        )
        .unwrap();
        conn.execute_batch(MIGRATION_V1).unwrap();
        conn.execute("INSERT INTO schema_version (version) VALUES (1)", [])
            .unwrap();
    }

    include!("schema/tests/admission.rs");
    include!("schema/tests/actual_handle_identity.rs");
    include!("schema/tests/windows_live_wal.rs");
    include!("schema/tests/dacl_isolation_windows.rs");
    include!("schema/tests/migrations.rs");
    include!("schema/tests/released.rs");
    include!("schema/tests/recovery_compatibility.rs");
    include!("schema/tests/credential_v24.rs");
    include!("schema/tests/credential_v24_invariants.rs");
    include!("schema/tests/credential_v24_observation_invariants.rs");
    include!("schema/tests/credential_v24_legacy_corruption.rs");
    include!("schema/tests/credential_v24_active_invariants.rs");
    include!("schema/tests/credential_v24_target_invariants.rs");
    include!("schema/tests/credential_v24_shape_invariants.rs");
    include!("schema/tests/credential_v24_owner_invariants.rs");
    include!("schema/tests/credential_v24_verification_ref_invariants.rs");
    include!("schema/tests/credential_v25.rs");
    include!("schema/tests/credential_v26.rs");
    include!("schema/tests/credential_v27.rs");
    include!("schema/tests/credential_v28.rs");
    include!("schema/tests/credential_v29.rs");
    include!("schema/tests/credential_v30.rs");
    include!("schema/tests/credential_v32.rs");
    include!("schema/tests/credential_v33.rs");
    include!("schema/tests/credential_v35.rs");
    include!("schema/tests/credential_v35_adversarial.rs");
    include!("schema/tests/project_workspace_v36.rs");
    include!("schema/tests/project_workspace_v39.rs");
    include!("schema/tests/frozen_migrations.rs");
    include!("schema/tests/provider_accounting_v37.rs");
}
