//! Migration control-plane application service.

use sha2::{Digest, Sha256};

pub use super::ports::CutoverIntent;

use super::{
    error::MigrationError,
    gates::{
        GateApplicabilityError, GateContext, GateSetValidationError, MigrationEvidence,
        PhaseGatePolicy, ValidatedGateSet,
    },
    manifests::{
        ArtifactRef, CandidateValidationReport, CutoverManifest, CutoverManifestFields,
        DrainReportArtifact, MigrationReport, RollbackPolicy,
    },
    ports::{
        LoadedMigrationPlan, MigrationAuditAction, MigrationAuditRecord, MigrationCommandContext,
        MigrationCommandFingerprint, MigrationCommandOutcome, MigrationCommit,
        MigrationCommitResult, MigrationControlStore, MigrationMutation, MigrationReceiptLookup,
        MigrationStoreError, MigrationTransition, ShadowExecutionPort,
    },
    rollout::CanaryPolicy,
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortSelector, FencingToken, MigrationPlanId, RollbackDisposition,
        RoutingGeneration, RoutingSnapshot, RuntimeAuthority,
    },
};

const COMMAND_FINGERPRINT_PREFIX: &[u8] = b"gocode-migration-command\x01";
const AUDIT_RECORD_PREFIX: &[u8] = b"gocode-migration-audit\x01";

/// Application facade for the eight migration control primitives.
pub struct MigrationService<S, H> {
    store: S,
    _shadow: H,
}

impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
    /// Construct the service from abstract persistence and shadow ports.
    pub fn new(store: S, shadow: H) -> Self {
        Self {
            store,
            _shadow: shadow,
        }
    }

    /// Load one durable migration plan.
    pub fn load_plan(
        &self,
        plan_id: &MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationError> {
        self.store.load_plan(plan_id).map_err(map_store_error)
    }

    /// Load the current routing head for an exact routing unit.
    pub fn routing_head(
        &self,
        unit: &super::types::RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationError> {
        self.store.load_routing_head(unit).map_err(map_store_error)
    }

    /// Stage a new Source-only migration plan.
    pub fn stage_plan(
        &self,
        context: MigrationCommandContext,
        input: StagePlanInput,
    ) -> Result<StagePlanOutput, MigrationError> {
        validate_stage_input(&context, &input)?;
        let fingerprint = fingerprint(
            1,
            vec![
                input.plan.plan_id.as_str().as_bytes().to_vec(),
                input.plan.cycle_id.as_str().as_bytes().to_vec(),
                input.plan.source.as_str().as_bytes().to_vec(),
                input.plan.candidate.as_str().as_bytes().to_vec(),
                input.plan.routing_unit.digest().as_bytes().to_vec(),
                input
                    .plan
                    .routing_unit
                    .feature_profile
                    .profile_digest
                    .as_bytes()
                    .to_vec(),
                input.plan.gate_policy.as_str().as_bytes().to_vec(),
                input
                    .initial_snapshot
                    .routing_generation
                    .get()
                    .to_be_bytes()
                    .to_vec(),
                input.initial_snapshot.fencing_token.as_bytes().to_vec(),
                vec![rollback_disposition_tag(
                    input.initial_snapshot.rollback_disposition,
                )],
                input
                    .initial_snapshot
                    .committed_at
                    .as_unix_micros()
                    .to_be_bytes()
                    .to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return stage_output(outcome);
        }

        let transition_id = transition_identity(&context, &fingerprint);
        let transition = MigrationTransition {
            transition_id: transition_id.clone(),
            plan_id: input.plan.plan_id.clone(),
            cycle_id: input.plan.cycle_id.clone(),
            from: MigrationPhase::Baseline,
            to: MigrationPhase::Baseline,
            plan_version: input.plan.plan_version,
            occurred_at: input.initial_snapshot.committed_at,
        };
        let outcome = MigrationCommandOutcome {
            plan: input.plan.clone(),
            routing_snapshot: Some(input.initial_snapshot.clone()),
            transition_id,
        };
        let audit = audit_record(
            &context,
            &input.plan,
            MigrationAuditAction::StagePlan,
            &fingerprint,
        );
        let commit = MigrationCommit::new(
            context,
            fingerprint,
            input.plan.clone(),
            vec![
                MigrationMutation::InsertPlan(input.plan),
                MigrationMutation::AppendTransition(transition),
                MigrationMutation::AppendRoutingSnapshot(input.initial_snapshot),
            ],
            outcome,
            Some(audit),
        )?;

        stage_output(commit_outcome(
            self.store.commit(commit).map_err(map_store_error)?,
        ))
    }

    /// Append immutable migration evidence.
    pub fn record_evidence(
        &self,
        context: MigrationCommandContext,
        input: RecordEvidenceInput,
    ) -> Result<RecordEvidenceOutput, MigrationError> {
        let fingerprint = fingerprint(
            2,
            vec![
                input.plan_id.as_str().as_bytes().to_vec(),
                input.evidence.semantic_digest().as_bytes().to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(record_evidence_output(outcome));
        }

        let loaded = self
            .store
            .load_plan(&input.plan_id)
            .map_err(map_store_error)?
            .ok_or(MigrationError::PlanNotFound)?;
        let mut plan = loaded.plan;
        validate_evidence_scope(&plan, &input.evidence)?;
        plan.record_mutation(context.expected_plan_version)?;

        let transition_id = transition_identity(&context, &fingerprint);
        let outcome = MigrationCommandOutcome {
            plan: plan.clone(),
            routing_snapshot: None,
            transition_id,
        };
        let audit = audit_record(
            &context,
            &plan,
            MigrationAuditAction::RecordEvidence,
            &fingerprint,
        );
        let commit = MigrationCommit::new(
            context,
            fingerprint,
            plan.clone(),
            vec![MigrationMutation::AppendEvidence(input.evidence)],
            outcome,
            Some(audit),
        )?;

        Ok(record_evidence_output(commit_outcome(
            self.store.commit(commit).map_err(map_store_error)?,
        )))
    }

    /// Advance a plan by exactly one phase.
    pub fn advance_phase(
        &self,
        context: MigrationCommandContext,
        plan_id: MigrationPlanId,
        target: MigrationPhase,
    ) -> Result<AdvancePhaseOutput, MigrationError> {
        let fingerprint = fingerprint(
            3,
            vec![
                plan_id.as_str().as_bytes().to_vec(),
                vec![phase_tag(target)],
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(advance_output(outcome));
        }

        let loaded = self
            .store
            .load_plan(&plan_id)
            .map_err(map_store_error)?
            .ok_or(MigrationError::PlanNotFound)?;
        let previous = loaded.plan.phase;
        let mut plan = loaded.plan.clone();
        plan.advance(target, context.expected_plan_version)?;
        validate_exit_evidence(&loaded, target)?;
        if target == MigrationPhase::InternalCanary {
            validate_production_gates(&loaded, &plan, target, context.evaluated_at)?;
        } else if matches!(
            target,
            MigrationPhase::CohortRollout
                | MigrationPhase::DefaultNative
                | MigrationPhase::DrainDeprecate
                | MigrationPhase::Retired
        ) {
            return Err(MigrationError::ProductionGatesUnavailable);
        }

        let transition_id = transition_identity(&context, &fingerprint);
        let transition = MigrationTransition {
            transition_id: transition_id.clone(),
            plan_id: plan.plan_id.clone(),
            cycle_id: plan.cycle_id.clone(),
            from: previous,
            to: target,
            plan_version: plan.plan_version,
            occurred_at: context.evaluated_at,
        };
        let outcome = MigrationCommandOutcome {
            plan: plan.clone(),
            routing_snapshot: None,
            transition_id,
        };
        let audit = audit_record(
            &context,
            &plan,
            MigrationAuditAction::AdvancePhase,
            &fingerprint,
        );
        let commit = MigrationCommit::new(
            context,
            fingerprint,
            plan.clone(),
            vec![MigrationMutation::AppendTransition(transition)],
            outcome,
            Some(audit),
        )?;

        Ok(advance_output(commit_outcome(
            self.store.commit(commit).map_err(map_store_error)?,
        )))
    }

    /// Freeze a currently valid Internal Canary evidence set without changing authority.
    pub fn prepare_cutover(
        &self,
        context: MigrationCommandContext,
        input: PrepareCutoverInput,
    ) -> Result<PrepareCutoverOutput, MigrationError> {
        let fingerprint = fingerprint(
            4,
            vec![
                input.plan_id.as_str().as_bytes().to_vec(),
                vec![cutover_intent_tag(input.intent)],
                input.canary_policy.admission_limit.to_be_bytes().to_vec(),
                artifact_fingerprint_bytes(&input.manifest),
                artifact_fingerprint_bytes(&input.source_release),
                artifact_fingerprint_bytes(&input.candidate_release),
                artifact_fingerprint_bytes(&input.migration_report.report),
                artifact_fingerprint_bytes(&input.drain_report.report),
                artifact_fingerprint_bytes(&input.candidate_validation.report),
                artifact_fingerprint_bytes(&input.frozen_evidence_set),
                artifact_fingerprint_bytes(&input.operator_authorization),
                rollback_policy_fingerprint_bytes(&input.rollback_policy),
                input
                    .retention_until
                    .as_unix_micros()
                    .to_be_bytes()
                    .to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(PrepareCutoverOutput { outcome });
        }
        let loaded = self
            .store
            .load_plan(&input.plan_id)
            .map_err(map_store_error)?
            .ok_or(MigrationError::PlanNotFound)?;
        if input.intent != CutoverIntent::InternalCanary
            || loaded.plan.phase != MigrationPhase::InternalCanary
        {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        validate_exit_evidence(&loaded, MigrationPhase::InternalCanary)?;
        let gate_set = validate_production_gates(
            &loaded,
            &loaded.plan,
            MigrationPhase::InternalCanary,
            context.evaluated_at,
        )?;
        if gate_set.digest() != input.frozen_evidence_set.digest {
            return Err(MigrationError::GateSetChanged);
        }
        let expected_routing_generation = context
            .expected_routing_generation
            .ok_or(MigrationError::ExpectedRoutingGenerationRequired)?;
        let routing_head = self
            .store
            .load_routing_head(&loaded.plan.routing_unit)
            .map_err(map_store_error)?
            .ok_or(MigrationError::StorageContractViolation)?;
        if routing_head.routing_generation != expected_routing_generation {
            return Err(MigrationError::RoutingGenerationConflict {
                expected: expected_routing_generation,
                actual: routing_head.routing_generation,
            });
        }

        let mut plan = loaded.plan;
        let expected_plan_version = context.expected_plan_version;
        plan.record_mutation(context.expected_plan_version)?;
        let transition_id = prepared_cutover_identity(&context, &plan.plan_id, gate_set.digest());
        let transition = MigrationTransition {
            transition_id: transition_id.clone(),
            plan_id: plan.plan_id.clone(),
            cycle_id: plan.cycle_id.clone(),
            from: plan.phase,
            to: plan.phase,
            plan_version: plan.plan_version,
            occurred_at: context.evaluated_at,
        };
        let manifest = CutoverManifest::new(CutoverManifestFields {
            manifest: input.manifest,
            plan_id: plan.plan_id.clone(),
            cycle_id: plan.cycle_id.clone(),
            intent: input.intent,
            canary_policy: input.canary_policy,
            routing_unit: plan.routing_unit.clone(),
            source_release: input.source_release,
            source_generation: plan.source.clone(),
            candidate_release: input.candidate_release,
            candidate_generation: plan.candidate.clone(),
            frozen_evidence_set: input.frozen_evidence_set,
            migration_report: input.migration_report.clone(),
            drain_report: input.drain_report,
            candidate_validation: input.candidate_validation,
            expected_routing_generation,
            routing_generation_at_prepare: routing_head.routing_generation,
            rollback_policy: input.rollback_policy,
            retention_until: input.retention_until,
            operator_authorization: input.operator_authorization,
            prepared_transition_id: transition_id.clone(),
            expected_plan_version,
            prepared_plan_version: plan.plan_version,
            prepared_at: context.evaluated_at,
        })?;
        let outcome = MigrationCommandOutcome {
            plan: plan.clone(),
            routing_snapshot: None,
            transition_id,
        };
        let audit = audit_record(
            &context,
            &plan,
            MigrationAuditAction::PrepareCutover,
            &fingerprint,
        );
        let commit = MigrationCommit::new(
            context,
            fingerprint,
            plan.clone(),
            vec![
                MigrationMutation::AppendTransition(transition),
                MigrationMutation::AppendMigrationReport(Box::new(input.migration_report)),
                MigrationMutation::AppendCutoverManifest(Box::new(manifest)),
            ],
            outcome,
            Some(audit),
        )?;
        Ok(PrepareCutoverOutput {
            outcome: commit_outcome(self.store.commit(commit).map_err(map_store_error)?),
        })
    }

    /// Revalidate a prepared cutover without enabling routing authority.
    pub fn commit_cutover(
        &self,
        context: MigrationCommandContext,
        input: CommitCutoverInput,
    ) -> Result<CommitCutoverOutput, MigrationError> {
        let fingerprint = fingerprint(
            5,
            vec![
                input.plan_id.as_str().as_bytes().to_vec(),
                input.prepared_transition_id.as_bytes().to_vec(),
                input.observed_source_high_water.to_be_bytes().to_vec(),
                input.candidate_fencing_token.as_bytes().to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(CommitCutoverOutput { outcome });
        }

        let loaded = self
            .store
            .load_plan(&input.plan_id)
            .map_err(map_store_error)?
            .ok_or(MigrationError::PlanNotFound)?;
        if loaded.plan.phase != MigrationPhase::InternalCanary {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        let manifest = loaded
            .cutover_manifests
            .iter()
            .find(|manifest| manifest.prepared_transition_id == input.prepared_transition_id)
            .ok_or(MigrationError::PreparedCutoverNotFound)?;
        if manifest.plan_id != loaded.plan.plan_id
            || manifest.cycle_id != loaded.plan.cycle_id
            || manifest.intent != CutoverIntent::InternalCanary
            || manifest.routing_unit != loaded.plan.routing_unit
            || !loaded
                .transitions
                .iter()
                .any(|transition| transition.transition_id == input.prepared_transition_id)
        {
            return Err(MigrationError::StorageContractViolation);
        }
        validate_exit_evidence(&loaded, MigrationPhase::InternalCanary)?;
        let gate_set = validate_production_gates(
            &loaded,
            &loaded.plan,
            MigrationPhase::InternalCanary,
            context.evaluated_at,
        )?;
        if manifest.evidence_set_digest != gate_set.digest()
            || !prepared_cutover_matches(&input.prepared_transition_id)
        {
            return Err(MigrationError::GateSetChanged);
        }
        if manifest.source_high_water != input.observed_source_high_water {
            return Err(MigrationError::StorageContractViolation);
        }
        let expected_routing_generation = context
            .expected_routing_generation
            .ok_or(MigrationError::ExpectedRoutingGenerationRequired)?;
        if manifest.expected_routing_generation != expected_routing_generation {
            return Err(MigrationError::RoutingGenerationConflict {
                expected: manifest.expected_routing_generation,
                actual: expected_routing_generation,
            });
        }
        let current_head = self
            .store
            .load_routing_head(&loaded.plan.routing_unit)
            .map_err(map_store_error)?
            .ok_or(MigrationError::StorageContractViolation)?;
        if current_head.routing_generation != expected_routing_generation
            || !matches!(current_head.authority, RuntimeAuthority::Source(_))
        {
            return Err(MigrationError::RoutingGenerationConflict {
                expected: expected_routing_generation,
                actual: current_head.routing_generation,
            });
        }
        let next_routing_generation = RoutingGeneration::new(
            expected_routing_generation
                .get()
                .checked_add(1)
                .ok_or(MigrationError::ArithmeticOverflow)?,
        )
        .map_err(|_| MigrationError::ArithmeticOverflow)?;
        let mut plan = loaded.plan;
        plan.record_mutation(context.expected_plan_version)?;
        let rollback_disposition = match manifest.rollback_policy {
            RollbackPolicy::ManualOnly => RollbackDisposition::Ineligible,
            RollbackPolicy::BeforeCandidateWrites | RollbackPolicy::ReverseMigrationRequired(_) => {
                RollbackDisposition::Eligible
            }
        };
        let snapshot = RoutingSnapshot::new(
            next_routing_generation,
            plan.source.clone(),
            plan.candidate.clone(),
            plan.phase,
            RuntimeAuthority::Candidate(plan.candidate.clone()),
            plan.routing_unit.clone(),
            input.candidate_fencing_token,
            rollback_disposition,
            context.evaluated_at,
        )
        .map_err(|_| MigrationError::StorageContractViolation)?;
        let transition_id = transition_identity(&context, &fingerprint);
        let transition = MigrationTransition {
            transition_id: transition_id.clone(),
            plan_id: plan.plan_id.clone(),
            cycle_id: plan.cycle_id.clone(),
            from: plan.phase,
            to: plan.phase,
            plan_version: plan.plan_version,
            occurred_at: context.evaluated_at,
        };
        let outcome = MigrationCommandOutcome {
            plan: plan.clone(),
            routing_snapshot: Some(snapshot.clone()),
            transition_id,
        };
        let audit = audit_record(
            &context,
            &plan,
            MigrationAuditAction::CommitCutover,
            &fingerprint,
        );
        let commit = MigrationCommit::new(
            context,
            fingerprint,
            plan.clone(),
            vec![
                MigrationMutation::AppendTransition(transition),
                MigrationMutation::AppendRoutingSnapshot(snapshot),
                MigrationMutation::AdvanceRoutingHead {
                    unit_digest: plan.routing_unit.digest(),
                    expected: expected_routing_generation,
                    next: next_routing_generation,
                },
            ],
            outcome,
            Some(audit),
        )?;
        Ok(CommitCutoverOutput {
            outcome: commit_outcome(self.store.commit(commit).map_err(map_store_error)?),
        })
    }

    /// Start an isolated Source-only rollback cycle.
    pub fn start_rollback_cycle(
        &self,
        context: MigrationCommandContext,
        input: StartRollbackInput,
    ) -> Result<StartRollbackOutput, MigrationError> {
        let fingerprint = fingerprint(
            6,
            vec![
                input.parent_plan_id.as_str().as_bytes().to_vec(),
                input.rollback_plan.plan_id.as_str().as_bytes().to_vec(),
                input.rollback_plan.cycle_id.as_str().as_bytes().to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return start_rollback_output(outcome);
        }

        let parent = self
            .store
            .load_plan(&input.parent_plan_id)
            .map_err(map_store_error)?
            .ok_or(MigrationError::PlanNotFound)?;
        validate_rollback_input(&context, &parent.plan, &input)?;

        let transition_id = transition_identity(&context, &fingerprint);
        let transition = MigrationTransition {
            transition_id: transition_id.clone(),
            plan_id: input.rollback_plan.plan_id.clone(),
            cycle_id: input.rollback_plan.cycle_id.clone(),
            from: MigrationPhase::Baseline,
            to: MigrationPhase::Baseline,
            plan_version: input.rollback_plan.plan_version,
            occurred_at: input.initial_snapshot.committed_at,
        };
        let outcome = MigrationCommandOutcome {
            plan: input.rollback_plan.clone(),
            routing_snapshot: Some(input.initial_snapshot.clone()),
            transition_id,
        };
        let audit = audit_record(
            &context,
            &input.rollback_plan,
            MigrationAuditAction::StartRollbackCycle,
            &fingerprint,
        );
        let commit = MigrationCommit::new_with_guard(
            context,
            fingerprint,
            input.parent_plan_id,
            input.rollback_plan.clone(),
            vec![
                MigrationMutation::InsertPlan(input.rollback_plan),
                MigrationMutation::AppendTransition(transition),
                MigrationMutation::AppendRoutingSnapshot(input.initial_snapshot),
            ],
            outcome,
            Some(audit),
        )?;

        start_rollback_output(commit_outcome(
            self.store.commit(commit).map_err(map_store_error)?,
        ))
    }

    /// Reject drain until production gates are implemented.
    pub fn begin_drain(
        &self,
        context: MigrationCommandContext,
        input: BeginDrainInput,
    ) -> Result<BeginDrainOutput, MigrationError> {
        let fingerprint = fingerprint(
            7,
            vec![
                input.plan_id.as_str().as_bytes().to_vec(),
                cohort_digest(&input.cohort).as_bytes().to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(BeginDrainOutput { outcome });
        }
        Err(MigrationError::ProductionGatesUnavailable)
    }

    /// Reject retirement until production gates are implemented.
    pub fn retire_source(
        &self,
        context: MigrationCommandContext,
        input: RetireSourceInput,
    ) -> Result<RetireSourceOutput, MigrationError> {
        let fingerprint = fingerprint(
            8,
            vec![
                input.plan_id.as_str().as_bytes().to_vec(),
                input.retirement_evidence_digest.as_bytes().to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(RetireSourceOutput { outcome });
        }
        Err(MigrationError::ProductionGatesUnavailable)
    }

    fn lookup_duplicate(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<Option<MigrationCommandOutcome>, MigrationError> {
        match self
            .store
            .lookup_receipt(context, fingerprint)
            .map_err(map_store_error)?
        {
            MigrationReceiptLookup::Miss => Ok(None),
            MigrationReceiptLookup::Duplicate { stored_result } => Ok(Some(*stored_result)),
        }
    }
}

/// Input for staging a migration plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlanInput {
    /// Baseline plan.
    pub plan: MigrationPlan,
    /// Initial Source-authoritative routing snapshot.
    pub initial_snapshot: RoutingSnapshot,
}

/// Successful stage result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlanOutput {
    /// Staged plan.
    pub plan: MigrationPlan,
    /// Initial Source-authoritative routing snapshot.
    pub snapshot: RoutingSnapshot,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Input for recording immutable evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEvidenceInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Evidence to append.
    pub evidence: MigrationEvidence,
}

/// Successful evidence append result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordEvidenceOutput {
    /// Updated plan version.
    pub plan: MigrationPlan,
    /// Durable mutation identity.
    pub transition_id: String,
}

/// Successful phase advance result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancePhaseOutput {
    /// Updated plan.
    pub plan: MigrationPlan,
    /// Routing snapshot committed by the operation, if any.
    pub snapshot: Option<RoutingSnapshot>,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Input for preparing a cutover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareCutoverInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Exact rollout intent.
    pub intent: CutoverIntent,
    /// Exact bounded Internal Canary admission policy.
    pub canary_policy: CanaryPolicy,
    /// Immutable content-addressed manifest identity.
    pub manifest: ArtifactRef,
    /// Exact source release artifact.
    pub source_release: ArtifactRef,
    /// Exact candidate release artifact.
    pub candidate_release: ArtifactRef,
    /// Frozen production gate set.
    pub frozen_evidence_set: ArtifactRef,
    /// Immutable one-way import report.
    pub migration_report: MigrationReport,
    /// Complete drain evidence.
    pub drain_report: DrainReportArtifact,
    /// Candidate rebuild and validation evidence.
    pub candidate_validation: CandidateValidationReport,
    /// Rollback policy frozen before routing CAS.
    pub rollback_policy: RollbackPolicy,
    /// Retention deadline for rollback artifacts.
    pub retention_until: gocode_domain::timestamp::Timestamp,
    /// Operator authorization evidence.
    pub operator_authorization: ArtifactRef,
}

/// Prepared cutover result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareCutoverOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for committing a prepared cutover.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCutoverInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Identity returned by preparation.
    pub prepared_transition_id: String,
    /// Source high-water observed immediately before routing CAS.
    pub observed_source_high_water: u64,
    /// Fresh fence token assigned to the candidate routing generation.
    pub candidate_fencing_token: FencingToken,
}

/// Committed cutover result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitCutoverOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for starting a rollback cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRollbackInput {
    /// Parent forward or rollback plan.
    pub parent_plan_id: MigrationPlanId,
    /// New isolated rollback plan.
    pub rollback_plan: MigrationPlan,
    /// Source-authoritative rollback snapshot.
    pub initial_snapshot: RoutingSnapshot,
}

/// Successful rollback-cycle creation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartRollbackOutput {
    /// New rollback plan.
    pub plan: MigrationPlan,
    /// Initial Source-authoritative rollback snapshot.
    pub snapshot: RoutingSnapshot,
    /// Durable transition identity.
    pub transition_id: String,
}

/// Input for beginning cohort drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDrainInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Exact cohort whose admission must close.
    pub cohort: CohortSelector,
}

/// Successful drain-start result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginDrainOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

/// Input for retiring source authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireSourceInput {
    /// Target plan.
    pub plan_id: MigrationPlanId,
    /// Immutable retirement evidence digest.
    pub retirement_evidence_digest: ArtifactDigest,
}

/// Successful source-retirement result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetireSourceOutput {
    /// Stored semantic outcome.
    pub outcome: MigrationCommandOutcome,
}

fn validate_stage_input(
    context: &MigrationCommandContext,
    input: &StagePlanInput,
) -> Result<(), MigrationError> {
    if input.plan.phase != MigrationPhase::Baseline
        || input.plan.status != MigrationPlanStatus::Active
        || input.plan.plan_version != 0
        || context.expected_plan_version != 0
    {
        return Err(MigrationError::StorageContractViolation);
    }
    if input.initial_snapshot.source != input.plan.source
        || input.initial_snapshot.candidate != input.plan.candidate
        || input.initial_snapshot.cohort != input.plan.routing_unit.cohort
        || input.initial_snapshot.contract_digest != input.plan.routing_unit.contract_digest
        || input.initial_snapshot.profile_digest
            != input.plan.routing_unit.feature_profile.profile_digest
        || input.initial_snapshot.config_digest != input.plan.routing_unit.config_digest
        || !matches!(
            &input.initial_snapshot.authority,
            RuntimeAuthority::Source(generation) if generation == &input.plan.source
        )
    {
        return Err(MigrationError::RoutingUnitMismatch);
    }
    Ok(())
}

fn validate_rollback_input(
    context: &MigrationCommandContext,
    parent: &MigrationPlan,
    input: &StartRollbackInput,
) -> Result<(), MigrationError> {
    if context.expected_plan_version != parent.plan_version {
        return Err(MigrationError::PlanVersionConflict {
            expected: context.expected_plan_version,
            actual: parent.plan_version,
        });
    }
    if input.rollback_plan.plan_id == parent.plan_id
        || input.rollback_plan.phase != MigrationPhase::Baseline
        || input.rollback_plan.plan_version != 0
        || input.rollback_plan.source != parent.candidate
        || input.rollback_plan.candidate != parent.source
        || !matches!(
            &input.rollback_plan.cycle_kind,
            MigrationCycleKind::Rollback { parent_cycle_id }
                if parent_cycle_id == &parent.cycle_id
        )
    {
        return Err(MigrationError::RollbackIneligible);
    }
    validate_stage_input(
        &MigrationCommandContext {
            expected_plan_version: 0,
            ..context.clone()
        },
        &StagePlanInput {
            plan: input.rollback_plan.clone(),
            initial_snapshot: input.initial_snapshot.clone(),
        },
    )
}

fn validate_exit_evidence(
    loaded: &LoadedMigrationPlan,
    target: MigrationPhase,
) -> Result<(), MigrationError> {
    let matching = loaded.evidence.iter().rev().find(|evidence| {
        matches!(
            (target, evidence),
            (
                MigrationPhase::Foundation,
                MigrationEvidence::Baseline { .. }
            ) | (
                MigrationPhase::ReadOnlyParity,
                MigrationEvidence::Foundation { .. }
            ) | (
                MigrationPhase::SimulatedShadow,
                MigrationEvidence::ReadOnlyParity { .. }
            ) | (
                MigrationPhase::InternalCanary,
                MigrationEvidence::SimulatedShadow { .. }
            )
        )
    });
    let evidence = matching.ok_or(MigrationError::EvidenceMissingForPhase { target })?;
    let proves_mutation = match evidence {
        MigrationEvidence::ReadOnlyParity {
            canonical_mutation_count,
            ..
        } => *canonical_mutation_count != 0,
        MigrationEvidence::SimulatedShadow {
            canonical_write_count,
            external_effect_count,
            client_acknowledgement_count,
            ..
        } => {
            *canonical_write_count != 0
                || *external_effect_count != 0
                || *client_acknowledgement_count != 0
        }
        MigrationEvidence::Baseline { .. }
        | MigrationEvidence::Foundation { .. }
        | MigrationEvidence::ProductionGate(_) => false,
    };
    if proves_mutation {
        Err(MigrationError::EvidenceProvesMutation { target })
    } else {
        Ok(())
    }
}

fn validate_production_gates(
    loaded: &LoadedMigrationPlan,
    plan: &MigrationPlan,
    target: MigrationPhase,
    now: gocode_domain::timestamp::Timestamp,
) -> Result<ValidatedGateSet, MigrationError> {
    let policy =
        PhaseGatePolicy::for_target(target).ok_or(MigrationError::ProductionGatesUnavailable)?;
    let context = GateContext {
        source_generation: plan.source.clone(),
        candidate_generation: plan.candidate.clone(),
        cohort: plan.routing_unit.cohort.clone(),
        contract_digest: plan.routing_unit.contract_digest,
        profile_digest: plan.routing_unit.feature_profile.profile_digest,
        config_digest: plan.routing_unit.config_digest,
        now,
    };
    policy
        .validate(&loaded.evidence, &context)
        .map_err(map_gate_set_error)
}

fn map_gate_set_error(error: GateSetValidationError) -> MigrationError {
    match error {
        GateSetValidationError::Missing { family } => MigrationError::GateMissing { family },
        GateSetValidationError::Inapplicable { family, reason } => match reason {
            GateApplicabilityError::Expired => MigrationError::GateExpired { family },
            GateApplicabilityError::Revoked => MigrationError::GateRevoked { family },
            GateApplicabilityError::NotYetValid
            | GateApplicabilityError::Failed
            | GateApplicabilityError::SourceGenerationMismatch
            | GateApplicabilityError::CandidateGenerationMismatch
            | GateApplicabilityError::CohortMismatch
            | GateApplicabilityError::ContractDigestMismatch
            | GateApplicabilityError::ProfileDigestMismatch
            | GateApplicabilityError::ConfigDigestMismatch
            | GateApplicabilityError::EmptyEvidenceDigest => MigrationError::GateFailed { family },
        },
    }
}

fn prepared_cutover_identity(
    context: &MigrationCommandContext,
    plan_id: &MigrationPlanId,
    evidence_set_digest: ArtifactDigest,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode-cutover-prepare\x01");
    update_length_prefixed(&mut hasher, plan_id.as_str().as_bytes());
    update_length_prefixed(&mut hasher, context.command_id.to_string().as_bytes());
    hasher.update(evidence_set_digest.as_bytes());
    let preparation_digest = ArtifactDigest::from_bytes(hasher.finalize().into());
    format!("cutover-prepare:{}", digest_hex(preparation_digest))
}

fn prepared_cutover_matches(prepared_transition_id: &str) -> bool {
    let mut parts = prepared_transition_id.split(':');
    matches!(
        (parts.next(), parts.next(), parts.next()),
        (Some("cutover-prepare"), Some(identity), None)
            if identity.len() == 64
                && identity.bytes().all(|byte| byte.is_ascii_hexdigit())
    )
}

fn digest_hex(digest: ArtifactDigest) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest.as_bytes() {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

fn artifact_fingerprint_bytes(artifact: &ArtifactRef) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(2 + artifact.reference.len() + 32);
    bytes.extend_from_slice(
        &u16::try_from(artifact.reference.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes(),
    );
    bytes.extend_from_slice(artifact.reference.as_bytes());
    bytes.extend_from_slice(artifact.digest.as_bytes());
    bytes
}

fn rollback_policy_fingerprint_bytes(policy: &RollbackPolicy) -> Vec<u8> {
    match policy {
        RollbackPolicy::BeforeCandidateWrites => vec![1],
        RollbackPolicy::ReverseMigrationRequired(contract) => {
            let mut bytes = vec![2];
            bytes.extend_from_slice(&artifact_fingerprint_bytes(contract));
            bytes
        }
        RollbackPolicy::ManualOnly => vec![3],
    }
}

fn validate_evidence_scope(
    plan: &MigrationPlan,
    evidence: &MigrationEvidence,
) -> Result<(), MigrationError> {
    let matches = match evidence {
        MigrationEvidence::Foundation {
            contract_digest, ..
        } => contract_digest == &plan.routing_unit.contract_digest,
        MigrationEvidence::ProductionGate(gate) => {
            gate.source_generation == plan.source
                && gate.candidate_generation == plan.candidate
                && gate.cohort == plan.routing_unit.cohort
                && gate.contract_digest == plan.routing_unit.contract_digest
                && gate.profile_digest == plan.routing_unit.feature_profile.profile_digest
                && gate.config_digest == plan.routing_unit.config_digest
        }
        MigrationEvidence::Baseline { .. }
        | MigrationEvidence::ReadOnlyParity { .. }
        | MigrationEvidence::SimulatedShadow { .. } => true,
    };
    if matches {
        Ok(())
    } else {
        Err(MigrationError::EvidenceScopeMismatch)
    }
}

fn stage_output(outcome: MigrationCommandOutcome) -> Result<StagePlanOutput, MigrationError> {
    let snapshot = outcome
        .routing_snapshot
        .ok_or(MigrationError::StorageContractViolation)?;
    Ok(StagePlanOutput {
        plan: outcome.plan,
        snapshot,
        transition_id: outcome.transition_id,
    })
}

fn record_evidence_output(outcome: MigrationCommandOutcome) -> RecordEvidenceOutput {
    RecordEvidenceOutput {
        plan: outcome.plan,
        transition_id: outcome.transition_id,
    }
}

fn advance_output(outcome: MigrationCommandOutcome) -> AdvancePhaseOutput {
    AdvancePhaseOutput {
        plan: outcome.plan,
        snapshot: outcome.routing_snapshot,
        transition_id: outcome.transition_id,
    }
}

fn start_rollback_output(
    outcome: MigrationCommandOutcome,
) -> Result<StartRollbackOutput, MigrationError> {
    let snapshot = outcome
        .routing_snapshot
        .ok_or(MigrationError::StorageContractViolation)?;
    Ok(StartRollbackOutput {
        plan: outcome.plan,
        snapshot,
        transition_id: outcome.transition_id,
    })
}

fn commit_outcome(result: MigrationCommitResult) -> MigrationCommandOutcome {
    match result {
        MigrationCommitResult::Committed { receipt } => receipt.stored_result,
        MigrationCommitResult::Duplicate { stored_result } => stored_result,
    }
}

fn audit_record(
    context: &MigrationCommandContext,
    plan: &MigrationPlan,
    action: MigrationAuditAction,
    fingerprint: &MigrationCommandFingerprint,
) -> MigrationAuditRecord {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_RECORD_PREFIX);
    update_length_prefixed(&mut hasher, context.command_id.to_string().as_bytes());
    hasher.update(fingerprint.as_bytes());
    MigrationAuditRecord {
        record_id: ArtifactDigest::from_bytes(hasher.finalize().into()),
        plan_id: plan.plan_id.clone(),
        command_id: context.command_id,
        operator_id: context.operator_id.clone(),
        action,
        recorded_at: context.evaluated_at,
    }
}

fn transition_identity(
    context: &MigrationCommandContext,
    fingerprint: &MigrationCommandFingerprint,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_RECORD_PREFIX);
    update_length_prefixed(&mut hasher, context.command_id.to_string().as_bytes());
    hasher.update(fingerprint.as_bytes());
    ArtifactDigest::from_bytes(hasher.finalize().into()).to_string()
}

fn fingerprint(tag: u8, fields: Vec<Vec<u8>>) -> MigrationCommandFingerprint {
    let mut hasher = Sha256::new();
    hasher.update(COMMAND_FINGERPRINT_PREFIX);
    hasher.update([tag]);
    for field in fields {
        update_length_prefixed(&mut hasher, &field);
    }
    MigrationCommandFingerprint::from_bytes(hasher.finalize().into())
}

fn cohort_digest(cohort: &CohortSelector) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode-migration-cohort\x01");
    for dimension in cohort.dimensions() {
        update_length_prefixed(&mut hasher, dimension.key().as_bytes());
        update_length_prefixed(&mut hasher, dimension.value().as_bytes());
    }
    ArtifactDigest::from_bytes(hasher.finalize().into())
}

fn update_length_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
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

fn cutover_intent_tag(intent: CutoverIntent) -> u8 {
    match intent {
        CutoverIntent::InternalCanary => 1,
        CutoverIntent::CohortExpansion => 2,
        CutoverIntent::DefaultNative => 3,
        CutoverIntent::Rollback => 4,
    }
}

fn rollback_disposition_tag(disposition: RollbackDisposition) -> u8 {
    match disposition {
        RollbackDisposition::Eligible => 1,
        RollbackDisposition::Ineligible => 2,
    }
}

fn map_store_error(error: MigrationStoreError) -> MigrationError {
    match error {
        MigrationStoreError::PlanVersionConflict { expected, actual } => {
            MigrationError::PlanVersionConflict { expected, actual }
        }
        MigrationStoreError::RoutingGenerationConflict { expected, actual } => {
            MigrationError::RoutingGenerationConflict { expected, actual }
        }
        MigrationStoreError::ArithmeticOverflow => MigrationError::ArithmeticOverflow,
        MigrationStoreError::CorruptData
        | MigrationStoreError::UnsupportedSchema
        | MigrationStoreError::Unavailable
        | MigrationStoreError::IdempotencyConflict
        | MigrationStoreError::IntegrityViolation
        | MigrationStoreError::RuntimeBindingConflict
        | MigrationStoreError::DispatchIntentConflict
        | MigrationStoreError::InvalidDispatchTransition => {
            MigrationError::StorageContractViolation
        }
    }
}
