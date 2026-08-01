fn exact_cohort<'a>(
    state: &'a DrainState,
    digest: ArtifactDigest,
    cohort: &CohortSelector,
) -> Result<&'a CohortState, RuntimeMigrationError> {
    let found = state
        .cohorts
        .get(&digest)
        .ok_or(RuntimeMigrationError::CohortNotRegistered)?;
    if found.cohort != *cohort {
        return Err(RuntimeMigrationError::CohortDigestCollision);
    }
    Ok(found)
}

fn exact_cohort_mut<'a>(
    state: &'a mut DrainState,
    digest: ArtifactDigest,
    cohort: &CohortSelector,
) -> Result<&'a mut CohortState, RuntimeMigrationError> {
    let found = state
        .cohorts
        .get_mut(&digest)
        .ok_or(RuntimeMigrationError::CohortNotRegistered)?;
    if found.cohort != *cohort {
        return Err(RuntimeMigrationError::CohortDigestCollision);
    }
    Ok(found)
}

fn validate_generation(
    state: &CohortState,
    attempted: RoutingGeneration,
) -> Result<(), RuntimeMigrationError> {
    if state.routing_generation == attempted {
        Ok(())
    } else {
        Err(RuntimeMigrationError::RoutingGenerationMismatch {
            expected: state.routing_generation,
            actual: attempted,
        })
    }
}

fn cohort_digest(cohort: &CohortSelector) -> ArtifactDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode-migration-drain-cohort\x01");
    hasher.update((cohort.dimensions().len() as u16).to_be_bytes());
    for dimension in cohort.dimensions() {
        hasher.update((dimension.key().len() as u16).to_be_bytes());
        hasher.update(dimension.key().as_bytes());
        hasher.update((dimension.value().len() as u16).to_be_bytes());
        hasher.update(dimension.value().as_bytes());
    }
    ArtifactDigest::from_bytes(hasher.finalize().into())
}
