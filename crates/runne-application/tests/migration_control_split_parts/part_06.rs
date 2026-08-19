impl MigrationControlStore for MemoryMigrationStore {
    fn load_plan(
        &self,
        plan_id: &MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .plans
            .get(plan_id.as_str())
            .cloned())
    }

    fn load_routing_head(
        &self,
        unit: &RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .heads
            .get(&unit.digest())
            .cloned())
    }

    fn lookup_receipt(
        &self,
        context: &MigrationCommandContext,
        fingerprint: &MigrationCommandFingerprint,
    ) -> Result<MigrationReceiptLookup, MigrationStoreError> {
        let state = self.state.lock().unwrap();
        let Some((stored_key, stored_fingerprint, stored_result)) =
            state.receipts.get(&context.command_id.to_string())
        else {
            return Ok(MigrationReceiptLookup::Miss);
        };
        if stored_key == &context.idempotency_key && stored_fingerprint == fingerprint {
            Ok(MigrationReceiptLookup::Duplicate {
                stored_result: Box::new(stored_result.clone()),
            })
        } else {
            Err(MigrationStoreError::IdempotencyConflict)
        }
    }

    fn commit(
        &self,
        commit: MigrationCommit,
    ) -> Result<MigrationCommitResult, MigrationStoreError> {
        let mut state = self.state.lock().unwrap();
        let command_key = commit.context().command_id.to_string();
        if let Some((stored_key, stored_fingerprint, stored_result)) =
            state.receipts.get(&command_key)
        {
            if stored_key == &commit.context().idempotency_key
                && stored_fingerprint == commit.fingerprint()
            {
                return Ok(MigrationCommitResult::Duplicate {
                    stored_result: stored_result.clone(),
                });
            }
            return Err(MigrationStoreError::IdempotencyConflict);
        }

        if let Some(existing) = state.plans.get(commit.guard_plan_id().as_str())
            && existing.plan.plan_version != commit.context().expected_plan_version
        {
            return Err(MigrationStoreError::PlanVersionConflict {
                expected: commit.context().expected_plan_version,
                actual: existing.plan.plan_version,
            });
        }

        let mutations = commit.mutations().to_vec();
        for mutation in &mutations {
            match mutation {
                MigrationMutation::InsertPlan(plan) => {
                    state.plans.insert(
                        plan.plan_id.to_string(),
                        LoadedMigrationPlan {
                            plan: plan.clone(),
                            transitions: Vec::new(),
                            evidence: Vec::new(),
                            migration_reports: Vec::new(),
                            cutover_manifests: Vec::new(),
                            rollback_manifests: Vec::new(),
                            retirement_manifests: Vec::new(),
                        },
                    );
                }
                MigrationMutation::AppendTransition(transition) => {
                    state
                        .plans
                        .get_mut(transition.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .transitions
                        .push(transition.clone());
                }
                MigrationMutation::AppendEvidence(evidence) => {
                    state
                        .plans
                        .get_mut(commit.plan().plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .evidence
                        .push(evidence.clone());
                }
                MigrationMutation::AppendMigrationReport(report) => {
                    state
                        .plans
                        .get_mut(report.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .migration_reports
                        .push(report.as_ref().clone());
                }
                MigrationMutation::AppendCutoverManifest(manifest) => {
                    state
                        .plans
                        .get_mut(manifest.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .cutover_manifests
                        .push(manifest.as_ref().clone());
                }
                MigrationMutation::AppendRollbackManifest(manifest) => {
                    state
                        .plans
                        .get_mut(manifest.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .rollback_manifests
                        .push(manifest.as_ref().clone());
                }
                MigrationMutation::AppendRetirementManifest(manifest) => {
                    state
                        .plans
                        .get_mut(manifest.plan_id.as_str())
                        .ok_or(MigrationStoreError::CorruptData)?
                        .retirement_manifests
                        .push(manifest.as_ref().clone());
                }
                MigrationMutation::AppendRoutingSnapshot(snapshot) => {
                    state
                        .heads
                        .insert(commit.plan().routing_unit.digest(), snapshot.clone());
                }
                MigrationMutation::AdvanceRoutingHead { .. }
                | MigrationMutation::InsertRuntimeBinding(_) => {}
            }
        }

        state
            .plans
            .get_mut(commit.plan().plan_id.as_str())
            .ok_or(MigrationStoreError::CorruptData)?
            .plan = commit.plan().clone();

        let outcome = commit.outcome().clone();
        state.audits.push(commit.audit().clone());
        let receipt = MigrationReceipt {
            command_id: commit.context().command_id,
            idempotency_key: commit.context().idempotency_key.clone(),
            fingerprint: *commit.fingerprint(),
            stored_result: outcome.clone(),
            committed_at: Timestamp::from_unix_micros(100),
        };
        state.receipts.insert(
            command_key,
            (
                commit.context().idempotency_key.clone(),
                *commit.fingerprint(),
                outcome,
            ),
        );
        Ok(MigrationCommitResult::Committed { receipt })
    }
}

#[derive(Clone, Copy)]
struct PureShadow;

impl ShadowExecutionPort for PureShadow {
    fn evaluate(
        &self,
        _input: SanitizedShadowInput,
    ) -> Result<ShadowDiffReport, ShadowExecutionError> {
        Err(ShadowExecutionError::InvalidInput)
    }
}

fn seeded_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let store = MemoryMigrationStore::default();
    let service = MigrationService::new(store.clone(), PureShadow);
    service.stage_plan(stage_context(), stage_input()).unwrap();
    (service, store)
}

fn shadow_ready_service() -> (
    MigrationService<MemoryMigrationStore, PureShadow>,
    MemoryMigrationStore,
) {
    let (service, store) = seeded_service();
    for target in [
        MigrationPhase::Foundation,
        MigrationPhase::ReadOnlyParity,
        MigrationPhase::SimulatedShadow,
    ] {
        service
            .record_evidence(
                next_context(&service),
                RecordEvidenceInput {
                    plan_id: plan_id(),
                    evidence: required_evidence_for(target),
                },
            )
            .unwrap();
        service
            .advance_phase(next_context(&service), plan_id(), target)
            .unwrap();
    }
    service
        .record_evidence(
            next_context(&service),
            RecordEvidenceInput {
                plan_id: plan_id(),
                evidence: MigrationEvidence::SimulatedShadow {
                    semantic_diff_digest: ArtifactDigest::from_bytes([14; 32]),
                    canonical_write_count: 0,
                    external_effect_count: 0,
                    client_acknowledgement_count: 0,
                },
            },
        )
        .unwrap();
    (service, store)
}
