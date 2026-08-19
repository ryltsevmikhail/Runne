fn cohort_digest(cohort: &CohortSelector) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"runne-migration-cohort\x01");
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

fn cutover_phase(intent: CutoverIntent) -> Result<MigrationPhase, MigrationError> {
    match intent {
        CutoverIntent::InternalCanary => Ok(MigrationPhase::InternalCanary),
        CutoverIntent::CohortExpansion => Ok(MigrationPhase::CohortRollout),
        CutoverIntent::DefaultNative => Ok(MigrationPhase::DefaultNative),
        CutoverIntent::Rollback => Ok(MigrationPhase::InternalCanary),
    }
}

fn authority_matches_cutover_intent(authority: &RuntimeAuthority, intent: CutoverIntent) -> bool {
    match intent {
        CutoverIntent::InternalCanary => matches!(authority, RuntimeAuthority::Source(_)),
        CutoverIntent::CohortExpansion | CutoverIntent::DefaultNative => {
            matches!(authority, RuntimeAuthority::Candidate(_))
        }
        CutoverIntent::Rollback => matches!(authority, RuntimeAuthority::Source(_)),
    }
}

fn validate_admission_expansion(
    loaded: &LoadedMigrationPlan,
    policy: &CutoverPolicy,
) -> Result<(), MigrationError> {
    let CutoverPolicy::CohortExpansion(step) = policy else {
        return Ok(());
    };
    if loaded
        .cutover_manifests
        .iter()
        .filter(|manifest| manifest.routing_unit == loaded.plan.routing_unit)
        .filter_map(|manifest| manifest.rollout_policy.admission_limit())
        .max()
        .is_some_and(|current_limit| step.admission_limit <= current_limit)
    {
        return Err(MigrationError::ProductionGatesUnavailable);
    }
    Ok(())
}

fn rollout_policy_fingerprint_bytes(policy: &CutoverPolicy) -> Vec<u8> {
    let mut bytes = Vec::new();
    match policy {
        CutoverPolicy::InternalCanary(policy) => {
            bytes.push(1);
            bytes.extend_from_slice(cohort_digest(&policy.target_cohort).as_bytes());
            bytes.extend_from_slice(&policy.admission_limit.to_be_bytes());
        }
        CutoverPolicy::CohortExpansion(step) => {
            bytes.push(2);
            bytes.extend_from_slice(&step.previous_routing_generation.get().to_be_bytes());
            bytes.extend_from_slice(cohort_digest(&step.target_cohort).as_bytes());
            bytes.extend_from_slice(&step.admission_limit.to_be_bytes());
            bytes.extend_from_slice(&step.observation_window.as_secs().to_be_bytes());
            bytes.extend_from_slice(&step.observation_window.subsec_nanos().to_be_bytes());
            bytes.extend_from_slice(&step.observed_from.as_unix_micros().to_be_bytes());
            bytes.extend_from_slice(&step.observed_until.as_unix_micros().to_be_bytes());
            bytes.extend_from_slice(
                &u64::try_from(step.required_gate_policy.as_str().len())
                    .unwrap_or(u64::MAX)
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(step.required_gate_policy.as_str().as_bytes());
        }
        CutoverPolicy::DefaultNative(policy) => {
            bytes.push(3);
            match policy {
                super::rollout::PreDispatchFallbackPolicy::Disabled => bytes.push(0),
                super::rollout::PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
                    source_profile,
                } => {
                    bytes.push(1);
                    bytes.extend_from_slice(
                        &u64::try_from(source_profile.profile_id.len())
                            .unwrap_or(u64::MAX)
                            .to_be_bytes(),
                    );
                    bytes.extend_from_slice(source_profile.profile_id.as_bytes());
                    bytes.extend_from_slice(&source_profile.profile_revision.to_be_bytes());
                    bytes.extend_from_slice(source_profile.profile_digest.as_bytes());
                }
            }
        }
    }
    bytes
}
