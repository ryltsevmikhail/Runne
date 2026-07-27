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
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{RoutingGeneration, RoutingSnapshot, RoutingUnit},
};
use gocode_domain::id::AggregateId;
use rusqlite::{
    Connection, Error as SqliteError, ErrorCode, OptionalExtension, Transaction,
    TransactionBehavior, params,
};
use sha2::{Digest, Sha256};

use crate::{
    migration_codec::{
        MigrationCodecError, decode_migration_evidence, decode_migration_outcome,
        decode_migration_plan, decode_migration_transition, decode_routing_snapshot,
        encode_migration_audit, encode_migration_evidence, encode_migration_outcome,
        encode_migration_plan, encode_migration_transition, encode_routing_snapshot,
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

        Ok(Some(LoadedMigrationPlan {
            plan,
            transitions,
            evidence,
        }))
    }

    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
        let connection = self.reader()?;
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

fn snapshot_matches_unit(snapshot: &RoutingSnapshot, unit: &RoutingUnit) -> bool {
    snapshot.cohort == unit.cohort
        && snapshot.contract_digest == unit.contract_digest
        && snapshot.profile_digest == unit.feature_profile.profile_digest
        && snapshot.config_digest == unit.config_digest
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
