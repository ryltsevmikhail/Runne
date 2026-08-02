impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
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

    /// Close admission for one cohort and advance the plan to DrainDeprecate.
    pub fn begin_drain(
        &self,
        _context: MigrationCommandContext,
        _input: BeginDrainInput,
    ) -> Result<BeginDrainOutput, MigrationError> {
        // Durable admission closure is not available yet; never claim a drain.
        Err(MigrationError::DrainBlocked)
    }

    /// Validate every Stage 8 exit condition and atomically retire Source.
    pub fn retire_source(
        &self,
        _context: MigrationCommandContext,
        _input: RetireSourceInput,
    ) -> Result<RetireSourceOutput, MigrationError> {
        Err(MigrationError::RetirementBlocked)
    }

    /// Immediately revoke candidate routing authority and restore Source.
    pub fn emergency_revoke(
        &self,
        context: MigrationCommandContext,
        input: EmergencyRevokeInput,
    ) -> Result<EmergencyRevokeOutput, MigrationError> {
        let fingerprint = fingerprint(
            9,
            vec![
                input.plan_id.as_str().as_bytes().to_vec(),
                artifact_fingerprint_bytes(&input.operator_authorization),
                input.emergency_reason.as_bytes().to_vec(),
                input.new_fencing_token.as_bytes().to_vec(),
            ],
        );
        if let Some(outcome) = self.lookup_duplicate(&context, &fingerprint)? {
            return Ok(EmergencyRevokeOutput { outcome });
        }

        let loaded = self
            .store
            .load_plan(&input.plan_id)
            .map_err(map_store_error)?
            .ok_or(MigrationError::PlanNotFound)?;
        if !matches!(
            loaded.plan.phase,
            MigrationPhase::InternalCanary
                | MigrationPhase::CohortRollout
                | MigrationPhase::DefaultNative
        ) {
            return Err(MigrationError::EmergencyRevokeIneligible);
        }

        let routing_head = self
            .store
            .load_routing_head(&loaded.plan.routing_unit)
            .map_err(map_store_error)?
            .ok_or(MigrationError::StorageContractViolation)?;
        if routing_head.rollback_disposition != RollbackDisposition::Eligible {
            return Err(MigrationError::EmergencyRevokeIneligible);
        }
        if let Some(expected) = context.expected_routing_generation
            && expected != routing_head.routing_generation
        {
            return Err(MigrationError::RoutingGenerationConflict {
                expected,
                actual: routing_head.routing_generation,
            });
        }

        let next_routing_generation = RoutingGeneration::new(
            routing_head
                .routing_generation
                .get()
                .checked_add(1)
                .ok_or(MigrationError::ArithmeticOverflow)?,
        )
        .map_err(|_| MigrationError::ArithmeticOverflow)?;

        let mut plan = loaded.plan;
        plan.record_mutation(context.expected_plan_version)?;

        let snapshot = RoutingSnapshot::new(
            next_routing_generation,
            plan.source.clone(),
            plan.candidate.clone(),
            plan.phase,
            RuntimeAuthority::Source(plan.source.clone()),
            plan.routing_unit.clone(),
            input.new_fencing_token,
            RollbackDisposition::Ineligible,
            context.evaluated_at,
        )
        .map_err(|_| MigrationError::StorageContractViolation)?;

        let transition_id = transition_identity(&context, &fingerprint);
        let previous = plan.phase;
        let transition = MigrationTransition {
            transition_id: transition_id.clone(),
            plan_id: plan.plan_id.clone(),
            cycle_id: plan.cycle_id.clone(),
            from: previous,
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
            MigrationAuditAction::EmergencyRevoke,
            &fingerprint,
        );
        let mut commit_context = context;
        commit_context.expected_routing_generation = Some(routing_head.routing_generation);
        let commit = MigrationCommit::new(
            commit_context,
            fingerprint,
            plan.clone(),
            vec![
                MigrationMutation::AppendTransition(transition),
                MigrationMutation::AppendRoutingSnapshot(snapshot),
                MigrationMutation::AdvanceRoutingHead {
                    unit_digest: plan.routing_unit.digest(),
                    expected: routing_head.routing_generation,
                    next: next_routing_generation,
                },
            ],
            outcome,
            Some(audit),
        )?;
        Ok(EmergencyRevokeOutput {
            outcome: commit_outcome(self.store.commit(commit).map_err(map_store_error)?),
        })
    }

}
