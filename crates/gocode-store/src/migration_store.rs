//! SQLite implementation of the migration control-plane persistence port.

use std::{
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use gocode_application::migration::{
    ports::{
        LoadedMigrationPlan, MigrationAuditAction, MigrationCommandContext,
        MigrationCommandFingerprint, MigrationCommit, MigrationCommitResult, MigrationControlStore,
        MigrationMutation, MigrationReceipt, MigrationReceiptLookup, MigrationStoreError,
    },
    rollout::PreDispatchFallbackPolicy,
    routing::{
        BindRuntimeRequest, DispatchClaim, DispatchIntentStatus, DispatchResultStatus,
        MigrationRoutingStore, RouteAdmission, RoutingDispatchIntent,
    },
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, RoutingGeneration, RoutingSnapshot, RoutingUnit, RuntimeAuthority,
        RuntimeBinding,
    },
};
use gocode_domain::{
    id::{AggregateId, CommandId, IdempotencyKey},
    timestamp::Timestamp,
};
use rusqlite::{
    Connection, Error as SqliteError, ErrorCode, OptionalExtension, Transaction,
    TransactionBehavior, params,
};
use sha2::{Digest, Sha256};

use crate::{
    migration_codec::{
        MigrationCodecError, decode_cutover_manifest, decode_migration_evidence,
        decode_migration_outcome, decode_migration_plan, decode_migration_report,
        decode_migration_transition, decode_retirement_manifest, decode_rollback_manifest,
        decode_routing_snapshot, decode_runtime_binding, encode_cutover_manifest,
        encode_migration_audit, encode_migration_evidence, encode_migration_outcome,
        encode_migration_plan, encode_migration_report, encode_migration_transition,
        encode_retirement_manifest, encode_rollback_manifest, encode_routing_snapshot,
        encode_runtime_binding,
    },
    schema::{apply_migrations, open_with_pragmas, run_startup_gates},
};

/// SQLite-backed migration control-plane store.
///
/// Writes are serialized through one connection and every atomic control
/// commit uses `BEGIN IMMEDIATE`. Reads use short-lived independent
/// connections opened from the same durable path.
#[derive(Clone)]
pub struct SqliteMigrationControlStore {
    path: PathBuf,
    writer: Arc<Mutex<Connection>>,
}

impl SqliteMigrationControlStore {
    /// Open a durable migration control store, apply migrations, and run
    /// startup integrity gates.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MigrationStoreError> {
        let path = path.as_ref().to_path_buf();
        let path_text = path.to_str().ok_or(MigrationStoreError::Unavailable)?;
        let writer = open_with_pragmas(path_text).map_err(map_open_error)?;
        apply_migrations(&writer).map_err(|_| MigrationStoreError::CorruptData)?;
        run_startup_gates(&writer, path_text)
            .map_err(|_| MigrationStoreError::IntegrityViolation)?;
        Ok(Self {
            path,
            writer: Arc::new(Mutex::new(writer)),
        })
    }

    fn reader(&self) -> Result<Connection, MigrationStoreError> {
        let connection = Connection::open(&self.path).map_err(map_open_error)?;
        connection
            .execute_batch(
                "PRAGMA foreign_keys = ON;
                 PRAGMA busy_timeout = 5000;",
            )
            .map_err(map_open_error)?;
        Ok(connection)
    }
}

include!("migration_store/types.rs");
include!("migration_store/load_plan.rs");
include!("migration_store/control_trait.rs");
include!("migration_store/routing.rs");
include!("migration_store/receipt.rs");
include!("migration_store/guards.rs");
include!("migration_store/persistence.rs");
include!("migration_store/results.rs");
include!("migration_store/routing_helpers.rs");
include!("migration_store/mapping.rs");
