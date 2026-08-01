impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
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
        if !matches!(
            loaded.plan.phase,
            MigrationPhase::InternalCanary
                | MigrationPhase::CohortRollout
                | MigrationPhase::DefaultNative
        ) {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        let manifest = loaded
            .cutover_manifests
            .iter()
            .find(|manifest| manifest.prepared_transition_id == input.prepared_transition_id)
            .ok_or(MigrationError::PreparedCutoverNotFound)?;
        let target_phase = cutover_phase(manifest.intent)?;
        if loaded.plan.phase != target_phase {
            return Err(MigrationError::ProductionGatesUnavailable);
        }
        if manifest.plan_id != loaded.plan.plan_id
            || manifest.cycle_id != loaded.plan.cycle_id
            || manifest.routing_unit != loaded.plan.routing_unit
            || !loaded
                .transitions
                .iter()
                .any(|transition| transition.transition_id == input.prepared_transition_id)
        {
            return Err(MigrationError::StorageContractViolation);
        }
        if target_phase == MigrationPhase::InternalCanary {
            validate_exit_evidence(&loaded, target_phase)?;
        }
        let gate_set =
            validate_production_gates(&loaded, &loaded.plan, target_phase, context.evaluated_at)?;
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
            || current_head.source != loaded.plan.source
            || current_head.candidate != loaded.plan.candidate
            || !authority_matches_cutover_intent(&current_head.authority, manifest.intent)
        {
            return Err(MigrationError::RoutingGenerationConflict {
                expected: expected_routing_generation,
                actual: current_head.routing_generation,
            });
        }
        manifest.rollout_policy.validate_for_prepare(
            manifest.intent,
            &loaded.plan.routing_unit,
            current_head.routing_generation,
            &loaded.plan.gate_policy,
            context.evaluated_at,
        )?;
        let next_routing_generation = RoutingGeneration::new(
            expected_routing_generation
                .get()
                .checked_add(1)
                .ok_or(MigrationError::ArithmeticOverflow)?,
        )
        .map_err(|_| MigrationError::ArithmeticOverflow)?;
        let mut plan = loaded.plan;
        plan.record_mutation(context.expected_plan_version)?;
        let rollback_disposition = if matches!(manifest.intent, CutoverIntent::Rollback) {
            RollbackDisposition::Ineligible
        } else {
            match manifest.rollback_policy {
                RollbackPolicy::ManualOnly => RollbackDisposition::Ineligible,
                RollbackPolicy::BeforeCandidateWrites
                | RollbackPolicy::ReverseMigrationRequired(_) => RollbackDisposition::Eligible,
            }
        };
        let (snapshot_source, snapshot_candidate, authority) = match manifest.intent {
            CutoverIntent::Rollback => (
                plan.candidate.clone(),
                plan.source.clone(),
                RuntimeAuthority::Source(plan.candidate.clone()),
            ),
            _ => (
                plan.source.clone(),
                plan.candidate.clone(),
                RuntimeAuthority::Candidate(plan.candidate.clone()),
            ),
        };
        let snapshot = RoutingSnapshot::new(
            next_routing_generation,
            snapshot_source,
            snapshot_candidate,
            plan.phase,
            authority,
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

}
