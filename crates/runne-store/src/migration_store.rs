//! SQLite implementation of the migration control-plane persistence port.

use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

use runne_application::migration::{
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
use runne_domain::{
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
    schema::{
        ConnectionMode, ManagedConnection, apply_migrations, open_managed_connection,
        publication_from_managed, readiness_from_managed,
    },
};

/// SQLite-backed migration control-plane store.
///
/// Reads and writes are serialized through one connection; every atomic
/// control commit uses `BEGIN IMMEDIATE`.
#[derive(Clone)]
pub struct SqliteMigrationControlStore {
    writer: Arc<Mutex<ManagedConnection>>,
}

impl SqliteMigrationControlStore {
    /// Open a durable migration control store, apply migrations, and run
    /// startup integrity gates.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MigrationStoreError> {
        let path_text = path
            .as_ref()
            .to_str()
            .ok_or(MigrationStoreError::Unavailable)?;
        let writer = open_managed_connection(path.as_ref(), ConnectionMode::Writer)
            .map_err(map_open_error)?;
        Self::open_with_connection(path_text, writer)
    }

    /// Adopts an already admitted writable connection for this store.
    ///
    /// The caller must retain a factory-managed writable connection admitted
    /// for this exact path. Validated reopen still verifies exact authority and
    /// event-log lineage identity before this adoption API is reached.
    pub fn open_with_connection(
        _path: &str,
        writer: ManagedConnection,
    ) -> Result<Self, MigrationStoreError> {
        apply_migrations(&writer).map_err(|_| MigrationStoreError::CorruptData)?;
        readiness_from_managed(&writer).map_err(|_| MigrationStoreError::IntegrityViolation)?;
        publication_from_managed(&writer).map_err(|_| MigrationStoreError::IntegrityViolation)?;
        Ok(Self {
            writer: Arc::new(Mutex::new(writer)),
        })
    }

    fn reader(&self) -> Result<MutexGuard<'_, ManagedConnection>, MigrationStoreError> {
        self.writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)
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
