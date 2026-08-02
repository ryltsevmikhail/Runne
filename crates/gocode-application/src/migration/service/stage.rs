impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
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
        if matches!(
            target,
            MigrationPhase::DrainDeprecate | MigrationPhase::Retired
        ) {
            return Err(MigrationError::SpecializedTransitionRequired { target });
        }
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
        if matches!(
            target,
            MigrationPhase::Foundation
                | MigrationPhase::ReadOnlyParity
                | MigrationPhase::SimulatedShadow
                | MigrationPhase::InternalCanary
        ) {
            validate_exit_evidence(&loaded, target)?;
        }
        if matches!(
            target,
            MigrationPhase::InternalCanary | MigrationPhase::CohortRollout
        ) {
            validate_production_gates(&loaded, &plan, target, context.evaluated_at)?;
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

}
