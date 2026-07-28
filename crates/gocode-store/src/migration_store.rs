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

impl MigrationControlStore for SqliteMigrationControlStore {
    fn load_plan(
        &self,
        plan_id: &gocode_application::migration::types::MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError> {
        let connection = self.reader()?;
        let row: Option<StoredPlanRow> = connection
            .query_row(
                "SELECT plan_id, cycle_id, cycle_kind, parent_cycle_id,
                        source_generation, candidate_generation, phase, status,
                        routing_unit_digest, gate_policy, plan_version, created_at,
                        plan_blob
                 FROM migration_plans
                 WHERE plan_id = ?1",
                [plan_id.as_str()],
                |row| {
                    Ok(StoredPlanRow {
                        plan_id: row.get(0)?,
                        cycle_id: row.get(1)?,
                        cycle_kind: row.get(2)?,
                        parent_cycle_id: row.get(3)?,
                        source_generation: row.get(4)?,
                        candidate_generation: row.get(5)?,
                        phase: row.get(6)?,
                        status: row.get(7)?,
                        routing_unit_digest: row.get(8)?,
                        gate_policy: row.get(9)?,
                        plan_version: row.get(10)?,
                        created_at: row.get(11)?,
                        plan_blob: row.get(12)?,
                    })
                },
            )
            .optional()
            .map_err(map_read_error)?;
        let Some(stored) = row else {
            return Ok(None);
        };
        let plan = decode_migration_plan(&stored.plan_blob).map_err(map_codec_error)?;
        if !stored.matches(&plan, plan_id)? {
            return Err(MigrationStoreError::CorruptData);
        }

        let mut transition_statement = connection
            .prepare(
                "SELECT transition_id, cycle_id, from_phase, to_phase,
                        plan_version, occurred_at, transition_blob
                 FROM migration_transitions
                 WHERE plan_id = ?1
                 ORDER BY plan_version, transition_id",
            )
            .map_err(map_read_error)?;
        let transition_rows = transition_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, Vec<u8>>(6)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut transitions = Vec::new();
        for row in transition_rows {
            let (identity, cycle_id, from, to, version, occurred_at, blob) =
                row.map_err(map_read_error)?;
            let transition = decode_migration_transition(&blob).map_err(map_codec_error)?;
            if transition.plan_id != *plan_id
                || transition.transition_id != identity
                || transition.cycle_id.as_str() != cycle_id
                || i64::from(phase_tag(transition.from)) != from
                || i64::from(phase_tag(transition.to)) != to
                || u64_to_i64(transition.plan_version)? != version
                || transition.occurred_at.as_unix_micros() != occurred_at
            {
                return Err(MigrationStoreError::CorruptData);
            }
            transitions.push(transition);
        }

        let mut evidence_statement = connection
            .prepare(
                "SELECT evidence_digest, evidence_blob
                 FROM migration_evidence
                 WHERE plan_id = ?1
                 ORDER BY recorded_at, evidence_digest",
            )
            .map_err(map_read_error)?;
        let evidence_rows = evidence_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?))
            })
            .map_err(map_read_error)?;
        let mut evidence = Vec::new();
        for row in evidence_rows {
            let (stored_digest, blob) = row.map_err(map_read_error)?;
            let computed_digest: [u8; 32] = Sha256::digest(&blob).into();
            if stored_digest != computed_digest {
                return Err(MigrationStoreError::CorruptData);
            }
            evidence.push(decode_migration_evidence(&blob).map_err(map_codec_error)?);
        }

        let mut report_statement = connection
            .prepare(
                "SELECT report_id, cycle_id, report_kind, report_blob, created_at
                 FROM migration_reports
                 WHERE plan_id = ?1
                 ORDER BY created_at, report_id",
            )
            .map_err(map_read_error)?;
        let report_rows = report_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut migration_reports = Vec::new();
        for row in report_rows {
            let (stored_digest, stored_cycle_id, report_kind, blob, created_at) =
                row.map_err(map_read_error)?;
            let report = decode_migration_report(&blob).map_err(map_codec_error)?;
            if report_kind != 1
                || stored_digest != report.report.digest.as_bytes()
                || report.plan_id != *plan_id
                || stored_cycle_id != report.cycle_id.as_str()
                || report.cycle_id != plan.cycle_id
                || report.source_generation != plan.source
                || report.candidate_generation != plan.candidate
                || report.schema.digest != plan.routing_unit.schema_digest
                || report.profile.digest != plan.routing_unit.feature_profile.profile_digest
                || report.created_at.as_unix_micros() != created_at
            {
                return Err(MigrationStoreError::CorruptData);
            }
            migration_reports.push(report);
        }

        let mut manifest_statement = connection
            .prepare(
                "SELECT manifest_id, cycle_id, manifest_blob, created_at
                 FROM cutover_manifests
                 WHERE plan_id = ?1
                 ORDER BY created_at, manifest_id",
            )
            .map_err(map_read_error)?;
        let manifest_rows = manifest_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut cutover_manifests = Vec::new();
        for row in manifest_rows {
            let (stored_digest, stored_cycle_id, blob, created_at) = row.map_err(map_read_error)?;
            let manifest = decode_cutover_manifest(&blob).map_err(map_codec_error)?;
            if stored_digest != manifest.manifest_digest.as_bytes()
                || manifest.plan_id != *plan_id
                || stored_cycle_id != manifest.cycle_id.as_str()
                || manifest.cycle_id != plan.cycle_id
                || manifest.routing_unit != plan.routing_unit
                || manifest.source_generation != plan.source
                || manifest.candidate_generation != plan.candidate
                || created_at != manifest.prepared_at.as_unix_micros()
                || !migration_reports.iter().any(|report| {
                    report.report == manifest.import_report
                        && report.source_high_water == manifest.source_high_water
                        && report.is_cutover_eligible()
                })
            {
                return Err(MigrationStoreError::CorruptData);
            }
            cutover_manifests.push(manifest);
        }

        let mut rollback_statement = connection
            .prepare(
                "SELECT manifest_id, cycle_id, parent_plan_id, manifest_blob, created_at
                 FROM rollback_manifests
                 WHERE plan_id = ?1
                 ORDER BY created_at, manifest_id",
            )
            .map_err(map_read_error)?;
        let rollback_rows = rollback_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut rollback_manifests = Vec::new();
        for row in rollback_rows {
            let (stored_digest, stored_cycle_id, parent_plan_id, blob, created_at) =
                row.map_err(map_read_error)?;
            let manifest = decode_rollback_manifest(&blob).map_err(map_codec_error)?;
            if stored_digest != manifest.manifest.digest.as_bytes()
                || manifest.plan_id != *plan_id
                || stored_cycle_id != manifest.cycle_id.as_str()
                || parent_plan_id != manifest.parent_plan_id.as_str()
                || created_at != manifest.created_at.as_unix_micros()
            {
                return Err(MigrationStoreError::CorruptData);
            }
            rollback_manifests.push(manifest);
        }

        let mut retirement_statement = connection
            .prepare(
                "SELECT manifest_id, cycle_id, manifest_blob, created_at
                 FROM retirement_manifests
                 WHERE plan_id = ?1
                 ORDER BY created_at, manifest_id",
            )
            .map_err(map_read_error)?;
        let retirement_rows = retirement_statement
            .query_map([plan_id.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(map_read_error)?;
        let mut retirement_manifests = Vec::new();
        for row in retirement_rows {
            let (stored_digest, stored_cycle_id, blob, created_at) = row.map_err(map_read_error)?;
            let manifest = decode_retirement_manifest(&blob).map_err(map_codec_error)?;
            if stored_digest != manifest.manifest.digest.as_bytes()
                || manifest.plan_id != *plan_id
                || stored_cycle_id != manifest.cycle_id.as_str()
                || created_at != manifest.created_at.as_unix_micros()
            {
                return Err(MigrationStoreError::CorruptData);
            }
            retirement_manifests.push(manifest);
        }

        Ok(Some(LoadedMigrationPlan {
            plan,
            transitions,
            evidence,
            migration_reports,
            cutover_manifests,
            rollback_manifests,
            retirement_manifests,
        }))
    }

    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
        let connection = self.reader()?;
        load_routing_head_on(&connection, unit)
    }

    fn lookup_receipt(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<MigrationReceiptLookup, MigrationStoreError> {
        let connection = self.reader()?;
        lookup_receipt_on(&connection, context, fingerprint)
    }

    fn commit(
        &self,
        commit: MigrationCommit,
    ) -> Result<MigrationCommitResult, MigrationStoreError> {
        reject_uncertified_lifecycle_mutations(&commit)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;

        match lookup_receipt_on(&transaction, commit.context(), commit.fingerprint())? {
            MigrationReceiptLookup::Duplicate { stored_result } => {
                return Ok(MigrationCommitResult::Duplicate {
                    stored_result: *stored_result,
                });
            }
            MigrationReceiptLookup::Miss => {}
        }

        validate_plan_guard(&transaction, &commit)?;
        validate_routing_guard(&transaction, &commit)?;
        validate_mutations(&commit)?;
        persist_mutations(&transaction, &commit)?;
        persist_result_plan(&transaction, &commit)?;
        persist_audit(&transaction, &commit)?;
        persist_receipt(&transaction, &commit)?;
        transaction.commit().map_err(map_write_error)?;

        let receipt = MigrationReceipt {
            command_id: commit.context().command_id,
            idempotency_key: commit.context().idempotency_key.clone(),
            fingerprint: *commit.fingerprint(),
            stored_result: commit.outcome().clone(),
            committed_at: commit.audit().recorded_at,
        };
        Ok(MigrationCommitResult::Committed { receipt })
    }
}

impl MigrationRoutingStore for SqliteMigrationControlStore {
    fn load_runtime_binding(
        &self,
        aggregate_id: AggregateId,
        routing_unit: &RoutingUnit,
    ) -> Result<Option<RuntimeBinding>, MigrationStoreError> {
        let connection = self.reader()?;
        load_runtime_binding_on(&connection, &aggregate_id, routing_unit)
    }

    fn load_dispatch_intent(
        &self,
        aggregate_id: AggregateId,
    ) -> Result<Option<RoutingDispatchIntent>, MigrationStoreError> {
        let connection = self.reader()?;
        load_dispatch_intent_on(&connection, &aggregate_id)
    }

    fn bind_and_create_dispatch_intent(
        &self,
        request: BindRuntimeRequest,
    ) -> Result<RouteAdmission, MigrationStoreError> {
        validate_bind_runtime_request(&request)?;
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;

        if let Some(binding) =
            load_runtime_binding_on(&transaction, &request.aggregate_id, &request.routing_unit)?
        {
            let intent = load_dispatch_intent_on(&transaction, &request.aggregate_id)?
                .ok_or(MigrationStoreError::IntegrityViolation)?;
            validate_existing_intent(&intent, &request)?;
            transaction.commit().map_err(map_write_error)?;
            return Ok(RouteAdmission::Existing { binding, intent });
        }

        let durable_snapshot = load_routing_head_on(&transaction, &request.routing_unit)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        if durable_snapshot.routing_generation != request.expected_snapshot.routing_generation {
            return Err(MigrationStoreError::RoutingGenerationConflict {
                expected: request.expected_snapshot.routing_generation,
                actual: durable_snapshot.routing_generation,
            });
        }
        if durable_snapshot != request.expected_snapshot {
            return Err(MigrationStoreError::IntegrityViolation);
        }

        let selected_authority = match &request.fallback_policy {
            PreDispatchFallbackPolicy::Disabled => durable_snapshot.authority.clone(),
            PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { source_profile } => {
                if !matches!(durable_snapshot.authority, RuntimeAuthority::Candidate(_))
                    || source_profile != &request.routing_unit.feature_profile
                {
                    return Err(MigrationStoreError::IntegrityViolation);
                }
                RuntimeAuthority::Source(durable_snapshot.source.clone())
            }
        };
        let runtime_generation = match &selected_authority {
            RuntimeAuthority::Source(generation) | RuntimeAuthority::Candidate(generation) => {
                generation.clone()
            }
        };
        let binding = RuntimeBinding::new(
            request.aggregate_id.clone(),
            selected_authority,
            runtime_generation,
            durable_snapshot.routing_generation,
            durable_snapshot.fencing_token,
            request.bound_at,
        )
        .map_err(|_| MigrationStoreError::IntegrityViolation)?;
        let intent = RoutingDispatchIntent {
            aggregate_id: request.aggregate_id.clone(),
            command_id: request.command_id,
            idempotency_key: request.idempotency_key.clone(),
            request_digest: request.request_digest,
            status: DispatchIntentStatus::Pending,
            created_at: request.bound_at,
            updated_at: request.bound_at,
        };
        let (aggregate_type, aggregate_bytes) = aggregate_parts(&request.aggregate_id)?;
        let binding_blob = encode_runtime_binding(&binding).map_err(map_codec_error)?;
        transaction
            .execute(
                "INSERT INTO runtime_bindings
                 (aggregate_type, aggregate_id, routing_unit_digest,
                  routing_generation, binding_blob)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    request.routing_unit.digest().as_bytes().as_slice(),
                    u64_to_i64(binding.routing_generation.get())?,
                    binding_blob,
                ],
            )
            .map_err(map_runtime_binding_write_error)?;
        transaction
            .execute(
                "INSERT INTO routing_dispatch_intents
                 (aggregate_type, aggregate_id, command_id, idempotency_key,
                  request_digest, dispatch_status, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    request.command_id.as_bytes().as_slice(),
                    request.idempotency_key.as_str().as_bytes(),
                    request.request_digest.as_bytes().as_slice(),
                    dispatch_status_tag(DispatchIntentStatus::Pending),
                    request.bound_at.as_unix_micros(),
                    request.bound_at.as_unix_micros(),
                ],
            )
            .map_err(map_dispatch_intent_write_error)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(RouteAdmission::Created { binding, intent })
    }

    fn claim_dispatch(
        &self,
        aggregate_id: AggregateId,
        command_id: CommandId,
        claimed_at: Timestamp,
    ) -> Result<DispatchClaim, MigrationStoreError> {
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;
        let current = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        if current.command_id != command_id {
            return Err(MigrationStoreError::DispatchIntentConflict);
        }
        if current.status != DispatchIntentStatus::Pending {
            transaction.commit().map_err(map_write_error)?;
            return Ok(DispatchClaim::Existing(current));
        }
        if claimed_at < current.updated_at {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let (aggregate_type, aggregate_bytes) = aggregate_parts(&aggregate_id)?;
        let changed = transaction
            .execute(
                "UPDATE routing_dispatch_intents
                 SET dispatch_status = ?1, updated_at = ?2
                 WHERE aggregate_type = ?3
                   AND aggregate_id = ?4
                   AND command_id = ?5
                   AND dispatch_status = ?6",
                params![
                    dispatch_status_tag(DispatchIntentStatus::Indeterminate),
                    claimed_at.as_unix_micros(),
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    command_id.as_bytes().as_slice(),
                    dispatch_status_tag(DispatchIntentStatus::Pending),
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let claimed = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(DispatchClaim::Claimed(claimed))
    }

    fn record_dispatch_result(
        &self,
        aggregate_id: AggregateId,
        command_id: CommandId,
        status: DispatchResultStatus,
        recorded_at: Timestamp,
    ) -> Result<RoutingDispatchIntent, MigrationStoreError> {
        let target = match status {
            DispatchResultStatus::Accepted => DispatchIntentStatus::Accepted,
            DispatchResultStatus::RejectedBeforeAcceptance => {
                DispatchIntentStatus::RejectedBeforeAcceptance
            }
        };
        let mut writer = self
            .writer
            .lock()
            .map_err(|_| MigrationStoreError::Unavailable)?;
        let transaction = writer
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_write_error)?;
        let current = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        if current.command_id != command_id {
            return Err(MigrationStoreError::DispatchIntentConflict);
        }
        if current.status == target {
            transaction.commit().map_err(map_write_error)?;
            return Ok(current);
        }
        if current.status != DispatchIntentStatus::Indeterminate || recorded_at < current.updated_at
        {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let (aggregate_type, aggregate_bytes) = aggregate_parts(&aggregate_id)?;
        let changed = transaction
            .execute(
                "UPDATE routing_dispatch_intents
                 SET dispatch_status = ?1, updated_at = ?2
                 WHERE aggregate_type = ?3
                   AND aggregate_id = ?4
                   AND command_id = ?5
                   AND dispatch_status = ?6",
                params![
                    dispatch_status_tag(target),
                    recorded_at.as_unix_micros(),
                    aggregate_type,
                    aggregate_bytes.as_slice(),
                    command_id.as_bytes().as_slice(),
                    dispatch_status_tag(DispatchIntentStatus::Indeterminate),
                ],
            )
            .map_err(map_write_error)?;
        if changed != 1 {
            return Err(MigrationStoreError::InvalidDispatchTransition);
        }
        let recorded = load_dispatch_intent_on(&transaction, &aggregate_id)?
            .ok_or(MigrationStoreError::IntegrityViolation)?;
        transaction.commit().map_err(map_write_error)?;
        Ok(recorded)
    }
}

struct StoredPlanRow {
    plan_id: String,
    cycle_id: String,
    cycle_kind: i64,
    parent_cycle_id: Option<String>,
    source_generation: String,
    candidate_generation: String,
    phase: i64,
    status: i64,
    routing_unit_digest: Vec<u8>,
    gate_policy: String,
    plan_version: i64,
    created_at: i64,
    plan_blob: Vec<u8>,
}

impl StoredPlanRow {
    fn matches(
        &self,
        plan: &MigrationPlan,
        expected_plan_id: &gocode_application::migration::types::MigrationPlanId,
    ) -> Result<bool, MigrationStoreError> {
        let (cycle_kind, parent_cycle_id) = cycle_parts(&plan.cycle_kind);
        Ok(self.plan_id == plan.plan_id.as_str()
            && &plan.plan_id == expected_plan_id
            && self.cycle_id == plan.cycle_id.as_str()
            && self.cycle_kind == cycle_kind
            && self.parent_cycle_id.as_deref() == parent_cycle_id
            && self.source_generation == plan.source.as_str()
            && self.candidate_generation == plan.candidate.as_str()
            && self.phase == i64::from(phase_tag(plan.phase))
            && self.status == i64::from(status_tag(plan.status))
            && self.routing_unit_digest == plan.routing_unit.digest().as_bytes()
            && self.gate_policy == plan.gate_policy.as_str()
            && self.plan_version == u64_to_i64(plan.plan_version)?
            && self.created_at == plan.created_at.as_unix_micros())
    }
}

fn lookup_receipt_on(
    connection: &Connection,
    context: &MigrationCommandContext,
    fingerprint: &MigrationCommandFingerprint,
) -> Result<MigrationReceiptLookup, MigrationStoreError> {
    let by_command: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = connection
        .query_row(
            "SELECT idempotency_key, fingerprint, outcome_blob
             FROM migration_receipts
             WHERE command_id = ?1",
            [context.command_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    if let Some((stored_key, stored_fingerprint, outcome_blob)) = by_command {
        if stored_key != context.idempotency_key.as_str().as_bytes()
            || stored_fingerprint != fingerprint.as_bytes()
        {
            return Err(MigrationStoreError::IdempotencyConflict);
        }
        return Ok(MigrationReceiptLookup::Duplicate {
            stored_result: Box::new(
                decode_migration_outcome(&outcome_blob).map_err(map_codec_error)?,
            ),
        });
    }

    let conflicting_scope_key: bool = connection
        .query_row(
            "SELECT EXISTS(
                 SELECT 1
                 FROM migration_receipts
                 WHERE scope_bytes = ?1 AND idempotency_key = ?2
             )",
            params![
                receipt_scope(context)?,
                context.idempotency_key.as_str().as_bytes()
            ],
            |row| row.get(0),
        )
        .map_err(map_read_error)?;
    if conflicting_scope_key {
        Err(MigrationStoreError::IdempotencyConflict)
    } else {
        Ok(MigrationReceiptLookup::Miss)
    }
}

fn validate_plan_guard(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let actual: Option<i64> = transaction
        .query_row(
            "SELECT plan_version FROM migration_plans WHERE plan_id = ?1",
            [commit.guard_plan_id().as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_read_error)?;
    let expected = commit.context().expected_plan_version;
    match actual {
        Some(actual) if actual < 0 => Err(MigrationStoreError::CorruptData),
        Some(actual) if u64::try_from(actual).ok() != Some(expected) => {
            Err(MigrationStoreError::PlanVersionConflict {
                expected,
                actual: u64::try_from(actual).map_err(|_| MigrationStoreError::CorruptData)?,
            })
        }
        Some(_) => Ok(()),
        None if expected == 0
            && commit.mutations().iter().any(|mutation| {
                matches!(
                    mutation,
                    MigrationMutation::InsertPlan(plan)
                        if &plan.plan_id == commit.guard_plan_id()
                )
            }) =>
        {
            Ok(())
        }
        None => Err(MigrationStoreError::PlanVersionConflict {
            expected,
            actual: 0,
        }),
    }
}

fn validate_routing_guard(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    for mutation in commit.mutations() {
        let MigrationMutation::AdvanceRoutingHead {
            unit_digest,
            expected,
            next,
        } = mutation
        else {
            continue;
        };
        if commit.context().expected_routing_generation != Some(*expected) {
            return Err(MigrationStoreError::IntegrityViolation);
        }
        let expected_next = expected
            .get()
            .checked_add(1)
            .ok_or(MigrationStoreError::ArithmeticOverflow)?;
        if next.get() != expected_next {
            return Err(MigrationStoreError::IntegrityViolation);
        }
        let actual: Option<i64> = transaction
            .query_row(
                "SELECT routing_generation
                 FROM routing_head
                 WHERE routing_unit_digest = ?1",
                [unit_digest.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_read_error)?;
        let actual = actual.ok_or(MigrationStoreError::IntegrityViolation)?;
        let actual = u64::try_from(actual).map_err(|_| MigrationStoreError::CorruptData)?;
        if actual != expected.get() {
            return Err(MigrationStoreError::RoutingGenerationConflict {
                expected: *expected,
                actual: RoutingGeneration::new(actual)
                    .map_err(|_| MigrationStoreError::CorruptData)?,
            });
        }
    }
    Ok(())
}

fn validate_mutations(commit: &MigrationCommit) -> Result<(), MigrationStoreError> {
    let unit = &commit.plan().routing_unit;
    for mutation in commit.mutations() {
        match mutation {
            MigrationMutation::InsertPlan(plan) if plan != commit.plan() => {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendTransition(transition)
                if transition.plan_id != commit.plan().plan_id
                    || transition.cycle_id != commit.plan().cycle_id =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendCutoverManifest(manifest)
                if manifest.plan_id != commit.plan().plan_id
                    || manifest.cycle_id != commit.plan().cycle_id
                    || manifest.plan_version != commit.plan().plan_version
                    || !manifest.has_valid_identity()
                    || !commit.mutations().iter().any(|candidate| {
                        matches!(
                            candidate,
                            MigrationMutation::AppendMigrationReport(report)
                                if report.report == manifest.import_report
                                    && report.source_high_water == manifest.source_high_water
                                    && report.is_cutover_eligible()
                        )
                    }) =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendMigrationReport(report)
                if report.plan_id != commit.plan().plan_id
                    || report.cycle_id != commit.plan().cycle_id
                    || !report.has_valid_identity() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendRollbackManifest(manifest)
                if manifest.plan_id != commit.plan().plan_id
                    || manifest.cycle_id != commit.plan().cycle_id
                    || !manifest.has_valid_identity() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendRetirementManifest(manifest)
                if manifest.plan_id != commit.plan().plan_id
                    || manifest.cycle_id != commit.plan().cycle_id
                    || !manifest.has_valid_identity() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendRoutingSnapshot(snapshot)
                if !snapshot_matches_unit(snapshot, unit)
                    || snapshot.source != commit.plan().source
                    || snapshot.candidate != commit.plan().candidate =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AdvanceRoutingHead { unit_digest, .. }
                if *unit_digest != unit.digest() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::InsertRuntimeBinding(binding)
                if matches!(binding.aggregate_id, AggregateId::Workspace(_)) =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            _ => {}
        }
    }
    Ok(())
}

fn reject_uncertified_lifecycle_mutations(
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let target = std::iter::once(commit.plan().phase)
        .chain(
            commit
                .mutations()
                .iter()
                .filter_map(|mutation| match mutation {
                    MigrationMutation::AppendTransition(transition) => Some(transition.to),
                    MigrationMutation::AppendRetirementManifest(_) => Some(MigrationPhase::Retired),
                    _ => None,
                }),
        )
        .find(|phase| {
            matches!(
                phase,
                MigrationPhase::DrainDeprecate | MigrationPhase::Retired
            )
        });

    match target {
        Some(target) => Err(MigrationStoreError::LifecycleAuthorityRequired { target }),
        None => Ok(()),
    }
}

fn persist_mutations(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let unit_digest = commit.plan().routing_unit.digest();
    let advances_head = commit
        .mutations()
        .iter()
        .any(|mutation| matches!(mutation, MigrationMutation::AdvanceRoutingHead { .. }));
    for mutation in commit.mutations() {
        match mutation {
            MigrationMutation::InsertPlan(plan) => insert_plan(transaction, plan)?,
            MigrationMutation::AppendTransition(transition) => {
                let blob = encode_migration_transition(transition).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO migration_transitions
                         (transition_id, plan_id, cycle_id, from_phase, to_phase,
                          plan_version, occurred_at, transition_blob)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                        params![
                            transition.transition_id,
                            transition.plan_id.as_str(),
                            transition.cycle_id.as_str(),
                            phase_tag(transition.from),
                            phase_tag(transition.to),
                            u64_to_i64(transition.plan_version)?,
                            transition.occurred_at.as_unix_micros(),
                            blob,
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendEvidence(evidence) => {
                let blob = encode_migration_evidence(evidence).map_err(map_codec_error)?;
                let digest: [u8; 32] = Sha256::digest(&blob).into();
                transaction
                    .execute(
                        "INSERT INTO migration_evidence
                         (evidence_digest, plan_id, evidence_blob, recorded_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            digest.as_slice(),
                            commit.plan().plan_id.as_str(),
                            blob,
                            commit.audit().recorded_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendMigrationReport(report) => {
                let blob = encode_migration_report(report).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO migration_reports
                         (report_id, plan_id, cycle_id, report_kind, report_blob, created_at)
                         VALUES (?1, ?2, ?3, 1, ?4, ?5)",
                        params![
                            report.report.digest.as_bytes().as_slice(),
                            report.plan_id.as_str(),
                            report.cycle_id.as_str(),
                            blob,
                            report.created_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendCutoverManifest(manifest) => {
                let blob = encode_cutover_manifest(manifest).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO cutover_manifests
                         (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            manifest.manifest_digest.as_bytes().as_slice(),
                            manifest.plan_id.as_str(),
                            manifest.cycle_id.as_str(),
                            blob,
                            manifest.prepared_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendRollbackManifest(manifest) => {
                let blob = encode_rollback_manifest(manifest).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO rollback_manifests
                         (manifest_id, plan_id, cycle_id, parent_plan_id, manifest_blob, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            manifest.manifest.digest.as_bytes().as_slice(),
                            manifest.plan_id.as_str(),
                            manifest.cycle_id.as_str(),
                            manifest.parent_plan_id.as_str(),
                            blob,
                            manifest.created_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendRetirementManifest(manifest) => {
                let blob = encode_retirement_manifest(manifest).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO retirement_manifests
                         (manifest_id, plan_id, cycle_id, manifest_blob, created_at)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            manifest.manifest.digest.as_bytes().as_slice(),
                            manifest.plan_id.as_str(),
                            manifest.cycle_id.as_str(),
                            blob,
                            manifest.created_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
            }
            MigrationMutation::AppendRoutingSnapshot(snapshot) => {
                let blob = encode_routing_snapshot(snapshot).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO routing_snapshots
                         (routing_unit_digest, routing_generation, snapshot_blob, committed_at)
                         VALUES (?1, ?2, ?3, ?4)",
                        params![
                            unit_digest.as_bytes().as_slice(),
                            u64_to_i64(snapshot.routing_generation.get())?,
                            blob,
                            snapshot.committed_at.as_unix_micros(),
                        ],
                    )
                    .map_err(map_write_error)?;
                if !advances_head && matches!(commit.plan().cycle_kind, MigrationCycleKind::Forward)
                {
                    transaction
                        .execute(
                            "INSERT INTO routing_head
                             (routing_unit_digest, routing_generation)
                             VALUES (?1, ?2)",
                            params![
                                unit_digest.as_bytes().as_slice(),
                                u64_to_i64(snapshot.routing_generation.get())?,
                            ],
                        )
                        .map_err(map_write_error)?;
                }
            }
            MigrationMutation::AdvanceRoutingHead {
                unit_digest,
                expected,
                next,
            } => {
                let changed = transaction
                    .execute(
                        "UPDATE routing_head
                         SET routing_generation = ?1
                         WHERE routing_unit_digest = ?2 AND routing_generation = ?3",
                        params![
                            u64_to_i64(next.get())?,
                            unit_digest.as_bytes().as_slice(),
                            u64_to_i64(expected.get())?,
                        ],
                    )
                    .map_err(map_write_error)?;
                if changed != 1 {
                    return Err(MigrationStoreError::IntegrityViolation);
                }
            }
            MigrationMutation::InsertRuntimeBinding(binding) => {
                let (aggregate_type, aggregate_id) = aggregate_parts(&binding.aggregate_id)?;
                let blob = encode_runtime_binding(binding).map_err(map_codec_error)?;
                transaction
                    .execute(
                        "INSERT INTO runtime_bindings
                         (aggregate_type, aggregate_id, routing_unit_digest,
                          routing_generation, binding_blob)
                         VALUES (?1, ?2, ?3, ?4, ?5)",
                        params![
                            aggregate_type,
                            aggregate_id.as_slice(),
                            unit_digest.as_bytes().as_slice(),
                            u64_to_i64(binding.routing_generation.get())?,
                            blob,
                        ],
                    )
                    .map_err(map_write_error)?;
            }
        }
    }
    Ok(())
}

fn insert_plan(
    transaction: &Transaction<'_>,
    plan: &MigrationPlan,
) -> Result<(), MigrationStoreError> {
    let blob = encode_migration_plan(plan).map_err(map_codec_error)?;
    let (cycle_kind, parent_cycle_id) = cycle_parts(&plan.cycle_kind);
    transaction
        .execute(
            "INSERT INTO migration_plans
             (plan_id, cycle_id, cycle_kind, parent_cycle_id, source_generation,
              candidate_generation, phase, status, routing_unit_digest,
              gate_policy, plan_version, created_at, plan_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            params![
                plan.plan_id.as_str(),
                plan.cycle_id.as_str(),
                cycle_kind,
                parent_cycle_id,
                plan.source.as_str(),
                plan.candidate.as_str(),
                phase_tag(plan.phase),
                status_tag(plan.status),
                plan.routing_unit.digest().as_bytes().as_slice(),
                plan.gate_policy.as_str(),
                u64_to_i64(plan.plan_version)?,
                plan.created_at.as_unix_micros(),
                blob,
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn cycle_parts(cycle_kind: &MigrationCycleKind) -> (i64, Option<&str>) {
    match cycle_kind {
        MigrationCycleKind::Forward => (1, None),
        MigrationCycleKind::Rollback { parent_cycle_id } => (2, Some(parent_cycle_id.as_str())),
    }
}

fn persist_result_plan(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let inserted = commit.mutations().iter().any(
        |mutation| matches!(mutation, MigrationMutation::InsertPlan(plan) if plan == commit.plan()),
    );
    if inserted {
        return Ok(());
    }
    let plan = commit.plan();
    let blob = encode_migration_plan(plan).map_err(map_codec_error)?;
    let changed = transaction
        .execute(
            "UPDATE migration_plans
             SET phase = ?1, status = ?2, plan_version = ?3, plan_blob = ?4
             WHERE plan_id = ?5",
            params![
                phase_tag(plan.phase),
                status_tag(plan.status),
                u64_to_i64(plan.plan_version)?,
                blob,
                plan.plan_id.as_str(),
            ],
        )
        .map_err(map_write_error)?;
    if changed != 1 {
        return Err(MigrationStoreError::IntegrityViolation);
    }
    Ok(())
}

fn persist_audit(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let audit = commit.audit();
    let blob = encode_migration_audit(audit).map_err(map_codec_error)?;
    transaction
        .execute(
            "INSERT INTO migration_audit
             (record_id, plan_id, command_id, operator_id, action, recorded_at, record_blob)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                audit.record_id.as_bytes().as_slice(),
                audit.plan_id.as_str(),
                audit.command_id.as_bytes().as_slice(),
                audit.operator_id.as_str(),
                audit_action_tag(audit.action),
                audit.recorded_at.as_unix_micros(),
                blob,
            ],
        )
        .map_err(|_| MigrationStoreError::IntegrityViolation)?;
    Ok(())
}

fn persist_receipt(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let outcome = encode_migration_outcome(commit.outcome()).map_err(map_codec_error)?;
    transaction
        .execute(
            "INSERT INTO migration_receipts
             (command_id, plan_id, scope_bytes, idempotency_key, fingerprint,
              outcome_blob, committed_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                commit.context().command_id.as_bytes().as_slice(),
                commit.plan().plan_id.as_str(),
                receipt_scope(commit.context())?,
                commit.context().idempotency_key.as_str().as_bytes(),
                commit.fingerprint().as_bytes().as_slice(),
                outcome,
                commit.audit().recorded_at.as_unix_micros(),
            ],
        )
        .map_err(map_write_error)?;
    Ok(())
}

fn receipt_scope(context: &MigrationCommandContext) -> Result<Vec<u8>, MigrationStoreError> {
    let operator = context.operator_id.as_str().as_bytes();
    let length =
        u16::try_from(operator.len()).map_err(|_| MigrationStoreError::ArithmeticOverflow)?;
    let mut scope = b"gocode-migration-scope\x01".to_vec();
    scope.extend_from_slice(&length.to_be_bytes());
    scope.extend_from_slice(operator);
    Ok(scope)
}

fn validate_bind_runtime_request(request: &BindRuntimeRequest) -> Result<(), MigrationStoreError> {
    if matches!(request.aggregate_id, AggregateId::Workspace(_))
        || request.request_digest.as_bytes() == &[0; 32]
        || !snapshot_matches_unit(&request.expected_snapshot, &request.routing_unit)
        || request.bound_at < request.expected_snapshot.committed_at
    {
        return Err(MigrationStoreError::IntegrityViolation);
    }
    Ok(())
}

fn validate_existing_intent(
    intent: &RoutingDispatchIntent,
    request: &BindRuntimeRequest,
) -> Result<(), MigrationStoreError> {
    if intent.aggregate_id != request.aggregate_id
        || intent.command_id != request.command_id
        || intent.idempotency_key != request.idempotency_key
        || intent.request_digest != request.request_digest
    {
        return Err(MigrationStoreError::DispatchIntentConflict);
    }
    Ok(())
}

fn load_routing_head_on(
    connection: &Connection,
    unit: &RoutingUnit,
) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
    let unit_digest = unit.digest();
    let row: Option<(i64, Vec<u8>)> = connection
        .query_row(
            "SELECT h.routing_generation, s.snapshot_blob
             FROM routing_head h
             JOIN routing_snapshots s
               ON s.routing_unit_digest = h.routing_unit_digest
              AND s.routing_generation = h.routing_generation
             WHERE h.routing_unit_digest = ?1",
            [unit_digest.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((stored_generation, snapshot_blob)) = row else {
        return Ok(None);
    };
    let snapshot = decode_routing_snapshot(&snapshot_blob).map_err(map_codec_error)?;
    if stored_generation != u64_to_i64(snapshot.routing_generation.get())?
        || !snapshot_matches_unit(&snapshot, unit)
    {
        return Err(MigrationStoreError::CorruptData);
    }
    Ok(Some(snapshot))
}

fn load_runtime_binding_on(
    connection: &Connection,
    aggregate_id: &AggregateId,
    routing_unit: &RoutingUnit,
) -> Result<Option<RuntimeBinding>, MigrationStoreError> {
    let (aggregate_type, aggregate_bytes) = aggregate_parts(aggregate_id)?;
    let row: Option<StoredRuntimeBindingRow> = connection
        .query_row(
            "SELECT b.routing_unit_digest, b.routing_generation, b.binding_blob,
                    s.snapshot_blob
             FROM runtime_bindings b
             JOIN routing_snapshots s
               ON s.routing_unit_digest = b.routing_unit_digest
              AND s.routing_generation = b.routing_generation
             WHERE b.aggregate_type = ?1 AND b.aggregate_id = ?2",
            params![aggregate_type, aggregate_bytes.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((stored_unit_digest, stored_generation, binding_blob, snapshot_blob)) = row else {
        return Ok(None);
    };
    if stored_unit_digest != routing_unit.digest().as_bytes() {
        return Err(MigrationStoreError::RuntimeBindingConflict);
    }
    let binding = decode_runtime_binding(&binding_blob).map_err(map_codec_error)?;
    let snapshot = decode_routing_snapshot(&snapshot_blob).map_err(map_codec_error)?;
    if &binding.aggregate_id != aggregate_id
        || stored_generation != u64_to_i64(binding.routing_generation.get())?
        || !snapshot_matches_unit(&snapshot, routing_unit)
        || binding.routing_generation != snapshot.routing_generation
        || binding.authority != snapshot.authority
        || binding.fencing_token != snapshot.fencing_token
        || binding.bound_at < snapshot.committed_at
    {
        return Err(MigrationStoreError::CorruptData);
    }
    Ok(Some(binding))
}

type StoredRuntimeBindingRow = (Vec<u8>, i64, Vec<u8>, Vec<u8>);

fn load_dispatch_intent_on(
    connection: &Connection,
    aggregate_id: &AggregateId,
) -> Result<Option<RoutingDispatchIntent>, MigrationStoreError> {
    let (aggregate_type, aggregate_bytes) = aggregate_parts(aggregate_id)?;
    let row: Option<StoredDispatchIntentRow> = connection
        .query_row(
            "SELECT command_id, idempotency_key, request_digest,
                    dispatch_status, created_at, updated_at
             FROM routing_dispatch_intents
             WHERE aggregate_type = ?1 AND aggregate_id = ?2",
            params![aggregate_type, aggregate_bytes.as_slice()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()
        .map_err(map_read_error)?;
    let Some((command_bytes, idempotency_bytes, digest_bytes, status, created_at, updated_at)) =
        row
    else {
        return Ok(None);
    };
    let command_id = decode_command_id(&command_bytes)?;
    let idempotency_key = std::str::from_utf8(&idempotency_bytes)
        .map_err(|_| MigrationStoreError::CorruptData)
        .and_then(|value| {
            IdempotencyKey::new(value.to_owned()).map_err(|_| MigrationStoreError::CorruptData)
        })?;
    let request_digest = ArtifactDigest::from_bytes(
        digest_bytes
            .try_into()
            .map_err(|_| MigrationStoreError::CorruptData)?,
    );
    if request_digest.as_bytes() == &[0; 32] || updated_at < created_at {
        return Err(MigrationStoreError::CorruptData);
    }
    Ok(Some(RoutingDispatchIntent {
        aggregate_id: aggregate_id.clone(),
        command_id,
        idempotency_key,
        request_digest,
        status: decode_dispatch_status(status)?,
        created_at: Timestamp::from_unix_micros(created_at),
        updated_at: Timestamp::from_unix_micros(updated_at),
    }))
}

type StoredDispatchIntentRow = (Vec<u8>, Vec<u8>, Vec<u8>, i64, i64, i64);

fn decode_command_id(bytes: &[u8]) -> Result<CommandId, MigrationStoreError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| MigrationStoreError::CorruptData)?;
    CommandId::from_bytes(bytes)
        .to_string()
        .parse()
        .map_err(|_| MigrationStoreError::CorruptData)
}

fn decode_dispatch_status(value: i64) -> Result<DispatchIntentStatus, MigrationStoreError> {
    match value {
        1 => Ok(DispatchIntentStatus::Pending),
        2 => Ok(DispatchIntentStatus::Indeterminate),
        3 => Ok(DispatchIntentStatus::Accepted),
        4 => Ok(DispatchIntentStatus::RejectedBeforeAcceptance),
        _ => Err(MigrationStoreError::CorruptData),
    }
}

const fn dispatch_status_tag(status: DispatchIntentStatus) -> i64 {
    match status {
        DispatchIntentStatus::Pending => 1,
        DispatchIntentStatus::Indeterminate => 2,
        DispatchIntentStatus::Accepted => 3,
        DispatchIntentStatus::RejectedBeforeAcceptance => 4,
    }
}

fn snapshot_matches_unit(snapshot: &RoutingSnapshot, unit: &RoutingUnit) -> bool {
    snapshot.cohort == unit.cohort
        && snapshot.contract_digest == unit.contract_digest
        && snapshot.profile_digest == unit.feature_profile.profile_digest
        && snapshot.config_digest == unit.config_digest
}

fn map_runtime_binding_write_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else if is_constraint(&error) {
        MigrationStoreError::RuntimeBindingConflict
    } else {
        MigrationStoreError::IntegrityViolation
    }
}

fn map_dispatch_intent_write_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else if is_constraint(&error) {
        MigrationStoreError::DispatchIntentConflict
    } else {
        MigrationStoreError::IntegrityViolation
    }
}

fn aggregate_parts(aggregate_id: &AggregateId) -> Result<(i64, [u8; 16]), MigrationStoreError> {
    match aggregate_id {
        AggregateId::TaskRun(id) => Ok((1, *id.as_bytes())),
        AggregateId::Conversation(id) => Ok((2, *id.as_bytes())),
        AggregateId::Workspace(_) => Err(MigrationStoreError::IntegrityViolation),
    }
}

fn phase_tag(phase: MigrationPhase) -> u8 {
    match phase {
        MigrationPhase::Baseline => 0,
        MigrationPhase::Foundation => 1,
        MigrationPhase::ReadOnlyParity => 2,
        MigrationPhase::SimulatedShadow => 3,
        MigrationPhase::InternalCanary => 4,
        MigrationPhase::CohortRollout => 5,
        MigrationPhase::DefaultNative => 6,
        MigrationPhase::DrainDeprecate => 7,
        MigrationPhase::Retired => 8,
    }
}

fn status_tag(status: MigrationPlanStatus) -> u8 {
    match status {
        MigrationPlanStatus::Active => 1,
        MigrationPlanStatus::Retired => 2,
    }
}

fn audit_action_tag(action: MigrationAuditAction) -> u8 {
    match action {
        MigrationAuditAction::StagePlan => 1,
        MigrationAuditAction::RecordEvidence => 2,
        MigrationAuditAction::AdvancePhase => 3,
        MigrationAuditAction::PrepareCutover => 4,
        MigrationAuditAction::CommitCutover => 5,
        MigrationAuditAction::StartRollbackCycle => 6,
        MigrationAuditAction::BeginDrain => 7,
        MigrationAuditAction::RetireSource => 8,
        MigrationAuditAction::EmergencyRevoke => 9,
    }
}

fn u64_to_i64(value: u64) -> Result<i64, MigrationStoreError> {
    i64::try_from(value).map_err(|_| MigrationStoreError::ArithmeticOverflow)
}

fn map_codec_error(error: MigrationCodecError) -> MigrationStoreError {
    match error {
        MigrationCodecError::UnknownVersion { .. } => MigrationStoreError::UnsupportedSchema,
        MigrationCodecError::Truncated
        | MigrationCodecError::TrailingBytes { .. }
        | MigrationCodecError::UnknownTag { .. }
        | MigrationCodecError::Oversized { .. }
        | MigrationCodecError::InvalidUtf8 { .. }
        | MigrationCodecError::InvalidValue { .. } => MigrationStoreError::CorruptData,
    }
}

fn map_open_error(_error: SqliteError) -> MigrationStoreError {
    MigrationStoreError::Unavailable
}

fn map_read_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else {
        MigrationStoreError::CorruptData
    }
}

fn map_write_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else {
        MigrationStoreError::IntegrityViolation
    }
}

fn is_busy(error: &SqliteError) -> bool {
    matches!(
        error,
        SqliteError::SqliteFailure(
            rusqlite::ffi::Error {
                code: ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}

fn is_constraint(error: &SqliteError) -> bool {
    matches!(
        error,
        SqliteError::SqliteFailure(
            rusqlite::ffi::Error {
                code: ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    )
}
