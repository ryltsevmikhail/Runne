fn validate_plan_guard(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let actual: Option<i64> = transaction
        .query_row(
            "SELECT plan_version FROM migration_plans WHERE plan_id = ?1",
            [commit.guard_plan_id().as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(map_read_error)?;
    let expected = commit.context().expected_plan_version;
    match actual {
        Some(actual) if actual < 0 => Err(MigrationStoreError::CorruptData),
        Some(actual) if u64::try_from(actual).ok() != Some(expected) => {
            Err(MigrationStoreError::PlanVersionConflict {
                expected,
                actual: u64::try_from(actual).map_err(|_| MigrationStoreError::CorruptData)?,
            })
        }
        Some(_) => Ok(()),
        None if expected == 0
            && commit.mutations().iter().any(|mutation| {
                matches!(
                    mutation,
                    MigrationMutation::InsertPlan(plan)
                        if &plan.plan_id == commit.guard_plan_id()
                )
            }) =>
        {
            Ok(())
        }
        None => Err(MigrationStoreError::PlanVersionConflict {
            expected,
            actual: 0,
        }),
    }
}

fn validate_routing_guard(
    transaction: &Transaction<'_>,
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    for mutation in commit.mutations() {
        let MigrationMutation::AdvanceRoutingHead {
            unit_digest,
            expected,
            next,
        } = mutation
        else {
            continue;
        };
        if commit.context().expected_routing_generation != Some(*expected) {
            return Err(MigrationStoreError::IntegrityViolation);
        }
        let expected_next = expected
            .get()
            .checked_add(1)
            .ok_or(MigrationStoreError::ArithmeticOverflow)?;
        if next.get() != expected_next {
            return Err(MigrationStoreError::IntegrityViolation);
        }
        let actual: Option<i64> = transaction
            .query_row(
                "SELECT routing_generation
                 FROM routing_head
                 WHERE routing_unit_digest = ?1",
                [unit_digest.as_bytes().as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(map_read_error)?;
        let actual = actual.ok_or(MigrationStoreError::IntegrityViolation)?;
        let actual = u64::try_from(actual).map_err(|_| MigrationStoreError::CorruptData)?;
        if actual != expected.get() {
            return Err(MigrationStoreError::RoutingGenerationConflict {
                expected: *expected,
                actual: RoutingGeneration::new(actual)
                    .map_err(|_| MigrationStoreError::CorruptData)?,
            });
        }
    }
    Ok(())
}

fn validate_mutations(commit: &MigrationCommit) -> Result<(), MigrationStoreError> {
    let unit = &commit.plan().routing_unit;
    for mutation in commit.mutations() {
        match mutation {
            MigrationMutation::InsertPlan(plan) if plan != commit.plan() => {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendTransition(transition)
                if transition.plan_id != commit.plan().plan_id
                    || transition.cycle_id != commit.plan().cycle_id =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendCutoverManifest(manifest)
                if manifest.plan_id != commit.plan().plan_id
                    || manifest.cycle_id != commit.plan().cycle_id
                    || manifest.plan_version != commit.plan().plan_version
                    || !manifest.has_valid_identity()
                    || !commit.mutations().iter().any(|candidate| {
                        matches!(
                            candidate,
                            MigrationMutation::AppendMigrationReport(report)
                                if report.report == manifest.import_report
                                    && report.source_high_water == manifest.source_high_water
                                    && report.is_cutover_eligible()
                        )
                    }) =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendMigrationReport(report)
                if report.plan_id != commit.plan().plan_id
                    || report.cycle_id != commit.plan().cycle_id
                    || !report.has_valid_identity() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendRollbackManifest(manifest)
                if manifest.plan_id != commit.plan().plan_id
                    || manifest.cycle_id != commit.plan().cycle_id
                    || !manifest.has_valid_identity() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendRetirementManifest(manifest)
                if manifest.plan_id != commit.plan().plan_id
                    || manifest.cycle_id != commit.plan().cycle_id
                    || !manifest.has_valid_identity() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AppendRoutingSnapshot(snapshot)
                if !snapshot_matches_unit(snapshot, unit)
                    || snapshot.source != commit.plan().source
                    || snapshot.candidate != commit.plan().candidate =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::AdvanceRoutingHead { unit_digest, .. }
                if *unit_digest != unit.digest() =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            MigrationMutation::InsertRuntimeBinding(binding)
                if matches!(binding.aggregate_id, AggregateId::Workspace(_)) =>
            {
                return Err(MigrationStoreError::IntegrityViolation);
            }
            _ => {}
        }
    }
    Ok(())
}

fn reject_uncertified_lifecycle_mutations(
    commit: &MigrationCommit,
) -> Result<(), MigrationStoreError> {
    let target = std::iter::once(commit.plan().phase)
        .chain(
            commit
                .mutations()
                .iter()
                .filter_map(|mutation| match mutation {
                    MigrationMutation::AppendTransition(transition) => Some(transition.to),
                    MigrationMutation::AppendRetirementManifest(_) => Some(MigrationPhase::Retired),
                    _ => None,
                }),
        )
        .find(|phase| {
            matches!(
                phase,
                MigrationPhase::DrainDeprecate | MigrationPhase::Retired
            )
        });

    match target {
        Some(target) => Err(MigrationStoreError::LifecycleAuthorityRequired { target }),
        None => Ok(()),
    }
}
