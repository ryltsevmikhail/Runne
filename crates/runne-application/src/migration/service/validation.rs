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
    now: runne_domain::timestamp::Timestamp,
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
