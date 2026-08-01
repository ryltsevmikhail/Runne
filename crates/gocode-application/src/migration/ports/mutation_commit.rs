/// Closed atomic mutations understood by the control store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationMutation {
    /// Insert a new plan.
    InsertPlan(MigrationPlan),
    /// Append a phase transition.
    AppendTransition(MigrationTransition),
    /// Append immutable evidence.
    AppendEvidence(MigrationEvidence),
    /// Append an immutable one-way import report.
    AppendMigrationReport(Box<MigrationReport>),
    /// Append an immutable cutover preparation manifest.
    AppendCutoverManifest(Box<CutoverManifest>),
    /// Append an immutable rollback-cycle manifest.
    AppendRollbackManifest(Box<RollbackManifest>),
    /// Append an immutable source-retirement manifest.
    AppendRetirementManifest(Box<RetirementManifest>),
    /// Append an immutable routing snapshot.
    AppendRoutingSnapshot(RoutingSnapshot),
    /// Compare-and-swap the routing head.
    AdvanceRoutingHead {
        /// Exact routing-unit digest.
        unit_digest: ArtifactDigest,
        /// Expected current routing generation.
        expected: RoutingGeneration,
        /// Next routing generation.
        next: RoutingGeneration,
    },
    /// Persist the immutable runtime binding for a new aggregate.
    InsertRuntimeBinding(RuntimeBinding),
}

impl MigrationMutation {
    fn has_same_identity_as(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::InsertPlan(left), Self::InsertPlan(right)) => left.plan_id == right.plan_id,
            (Self::AppendTransition(left), Self::AppendTransition(right)) => {
                left.transition_id == right.transition_id
            }
            (Self::AppendEvidence(left), Self::AppendEvidence(right)) => {
                left.identity_digest() == right.identity_digest()
            }
            (Self::AppendMigrationReport(left), Self::AppendMigrationReport(right)) => {
                left.report.digest == right.report.digest
            }
            (Self::AppendCutoverManifest(left), Self::AppendCutoverManifest(right)) => {
                left.manifest_digest == right.manifest_digest
            }
            (Self::AppendRollbackManifest(left), Self::AppendRollbackManifest(right)) => {
                left.manifest.digest == right.manifest.digest
            }
            (Self::AppendRetirementManifest(left), Self::AppendRetirementManifest(right)) => {
                left.manifest.digest == right.manifest.digest
            }
            (Self::AppendRoutingSnapshot(left), Self::AppendRoutingSnapshot(right)) => {
                left.routing_generation == right.routing_generation
            }
            (
                Self::AdvanceRoutingHead {
                    unit_digest: left, ..
                },
                Self::AdvanceRoutingHead {
                    unit_digest: right, ..
                },
            ) => left == right,
            (Self::InsertRuntimeBinding(left), Self::InsertRuntimeBinding(right)) => {
                left.aggregate_id == right.aggregate_id
            }
            _ => false,
        }
    }

    fn requires_expected_routing_generation(&self) -> bool {
        match self {
            Self::AppendRoutingSnapshot(snapshot) => {
                matches!(snapshot.authority, RuntimeAuthority::Candidate(_))
            }
            Self::AdvanceRoutingHead { .. } | Self::InsertRuntimeBinding(_) => true,
            Self::InsertPlan(_)
            | Self::AppendTransition(_)
            | Self::AppendEvidence(_)
            | Self::AppendMigrationReport(_)
            | Self::AppendCutoverManifest(_)
            | Self::AppendRollbackManifest(_)
            | Self::AppendRetirementManifest(_) => false,
        }
    }
}

/// Validated atomic control-plane commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommit {
    context: MigrationCommandContext,
    fingerprint: MigrationCommandFingerprint,
    guard_plan_id: MigrationPlanId,
    plan: MigrationPlan,
    mutations: Vec<MigrationMutation>,
    outcome: MigrationCommandOutcome,
    audit: MigrationAuditRecord,
}

impl MigrationCommit {
    /// Validate and construct an atomic commit payload.
    pub fn new(
        context: MigrationCommandContext,
        fingerprint: MigrationCommandFingerprint,
        plan: MigrationPlan,
        mutations: Vec<MigrationMutation>,
        outcome: MigrationCommandOutcome,
        audit: Option<MigrationAuditRecord>,
    ) -> Result<Self, MigrationError> {
        let guard_plan_id = plan.plan_id.clone();
        Self::new_with_guard(
            context,
            fingerprint,
            guard_plan_id,
            plan,
            mutations,
            outcome,
            audit,
        )
    }

    /// Validate a commit whose optimistic version guard belongs to another
    /// plan, as required when an isolated rollback cycle is created from an
    /// immutable parent.
    pub fn new_with_guard(
        context: MigrationCommandContext,
        fingerprint: MigrationCommandFingerprint,
        guard_plan_id: MigrationPlanId,
        plan: MigrationPlan,
        mutations: Vec<MigrationMutation>,
        outcome: MigrationCommandOutcome,
        audit: Option<MigrationAuditRecord>,
    ) -> Result<Self, MigrationError> {
        let audit = audit.ok_or(MigrationError::AuditUnavailable)?;

        if mutations
            .iter()
            .any(MigrationMutation::requires_expected_routing_generation)
            && context.expected_routing_generation.is_none()
        {
            return Err(MigrationError::ExpectedRoutingGenerationRequired);
        }

        if audit.plan_id != plan.plan_id
            || audit.command_id != context.command_id
            || audit.operator_id != context.operator_id
        {
            return Err(MigrationError::StorageContractViolation);
        }

        for (index, mutation) in mutations.iter().enumerate() {
            if mutations[index + 1..]
                .iter()
                .any(|candidate| mutation.has_same_identity_as(candidate))
            {
                return Err(MigrationError::StorageContractViolation);
            }
        }

        Ok(Self {
            context,
            fingerprint,
            guard_plan_id,
            plan,
            mutations,
            outcome,
            audit,
        })
    }

    /// Command context used for optimistic concurrency and idempotency.
    pub fn context(&self) -> &MigrationCommandContext {
        &self.context
    }

    /// Semantic fingerprint stored with the durable receipt.
    pub fn fingerprint(&self) -> &MigrationCommandFingerprint {
        &self.fingerprint
    }

    /// Plan whose durable version must match the command expectation.
    pub fn guard_plan_id(&self) -> &MigrationPlanId {
        &self.guard_plan_id
    }

    /// Resulting plan state.
    pub fn plan(&self) -> &MigrationPlan {
        &self.plan
    }

    /// Closed mutations applied by the adapter.
    pub fn mutations(&self) -> &[MigrationMutation] {
        &self.mutations
    }

    /// Semantic outcome stored with the durable receipt.
    pub fn outcome(&self) -> &MigrationCommandOutcome {
        &self.outcome
    }

    /// Audit record committed atomically with the mutations.
    pub fn audit(&self) -> &MigrationAuditRecord {
        &self.audit
    }
}

/// Result returned after an atomic store commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationCommitResult {
    /// New durable state and receipt were committed.
    Committed {
        /// Durable receipt containing the semantic outcome.
        receipt: MigrationReceipt,
    },
    /// The exact command was committed previously.
    Duplicate {
        /// Original semantic result.
        stored_result: MigrationCommandOutcome,
    },
}

impl MigrationCommitResult {
    /// Return the semantic outcome for either a new or duplicate commit.
    pub fn outcome(&self) -> &MigrationCommandOutcome {
        match self {
            Self::Committed { receipt } => &receipt.stored_result,
            Self::Duplicate { stored_result } => stored_result,
        }
    }

    /// Return the resulting plan.
    pub fn plan(&self) -> &MigrationPlan {
        &self.outcome().plan
    }
}
