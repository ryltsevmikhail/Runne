impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
    /// Freeze a currently valid phase-specific evidence set without changing authority.
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
                rollout_policy_fingerprint_bytes(&input.rollout_policy),
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
        let target_phase = cutover_phase(input.intent)?;
        if loaded.plan.phase != target_phase {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        if target_phase == MigrationPhase::InternalCanary {
            validate_exit_evidence(&loaded, target_phase)?;
        }
        let gate_set =
            validate_production_gates(&loaded, &loaded.plan, target_phase, context.evaluated_at)?;
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
        input.rollout_policy.validate_for_prepare(
            input.intent,
            &loaded.plan.routing_unit,
            routing_head.routing_generation,
            &loaded.plan.gate_policy,
            context.evaluated_at,
        )?;
        validate_admission_expansion(&loaded, &input.rollout_policy)?;

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
            rollout_policy: input.rollout_policy,
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

}
