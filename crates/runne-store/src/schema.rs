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
pub const CURRENT_SCHEMA_VERSION: i64 = 71;

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
#[cfg(target_os = "linux")]
include!("schema/admission_identity_linux.rs");
include!("schema/admission_open.rs");
include!("schema/admission_recovery.rs");
include!("schema/admission_classification.rs");
include!("schema/migration_control.rs");
include!("schema/validation.rs");
include!("schema/provider_validation.rs");
include!("schema/v12_snapshot.rs");
include!("schema/v12_fence.rs");
include!("schema/v12_rollback.rs");
include!("schema/no_admission_readiness.rs");
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
include!("schema/migrations/v35_provider_credential_revoke_cleanup_overlap.rs");
include!("schema/provider_qualification_v35_schema.rs");
include!("schema/provider_credential_v35_schema.rs");
include!("schema/migrations/v36_irreversible_revoke.rs");
include!("schema/provider_credential_v36_schema.rs");
include!("schema/migrations/v37_subscription_accounting.rs");
include!("schema/migrations/v38_subscription_budgets.rs");
include!("schema/migrations/v39_taskrun_lineage_origin.rs");
include!("schema/migrations/v40_conversation_context_scope.rs");
include!("schema/migrations/v41_execution_node.rs");
include!("schema/migrations/v42_taskrun_claim.rs");
include!("schema/migrations/v43_taskrun_occupation.rs");
include!("schema/migrations/v44_taskrun_dispatch_intent.rs");
include!("schema/migrations/v45_taskrun_no_effect_release.rs");
include!("schema/migrations/v46_taskrun_provider_binding.rs");
include!("schema/migrations/v47_text_only_taskrun_lineage.rs");
include!("schema/migrations/v48_conversation_writer_lease.rs");
include!("schema/migrations/v49_taskrun_terminal_settlement.rs");
include!("schema/migrations/v49_taskrun_local_terminal.rs");
include!("schema/migrations/v49_taskrun_local_no_effect.rs");
include!("schema/migrations/v50_provider_terminal_disposition.rs");
include!("schema/migrations/v51_taskrun_local_command.rs");
include!("schema/migrations/v52_secondary_profile_grants.rs");
include!("schema/migrations/v52_catalog_extensions.rs");
include!("schema/migrations/v53_taskrun_local_stop_receipt.rs");
include!("schema/migrations/v53_taskrun_local_stop_match.rs");
include!("schema/migrations/v54_provider_remote_response_binding.rs");
include!("schema/migrations/v55_provider_remote_terminal_artifact.rs");
include!("schema/migrations/v55_disposition_readiness.rs");
include!("schema/migrations/v56_provider_cancel_fence.rs");
include!("schema/migrations/v57_taskrun_unknown_successor.rs");
include!("schema/migrations/v58_provider_remote_operation_proof.rs");
include!("schema/migrations/v59_remote_terminal_settlement.rs");
include!("schema/migrations/v59_remote_terminal_source_readiness.rs");
include!("schema/migrations/v60_remote_artifact_cancel_closure.rs");
include!("schema/migrations/v61_remote_terminal_application.rs");
include!("schema/migrations/v62_remote_terminal_audit.rs");
include!("schema/migrations/v63_provider_terminal_unknown.rs");
include!("schema/recent_migrations.rs");

#[cfg(feature = "test-support")]
include!("schema/terminal_adoption_fixture.rs");
