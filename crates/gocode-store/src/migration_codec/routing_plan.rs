/// Encode one routing snapshot using migration codec version 1.
pub fn encode_routing_snapshot(snapshot: &RoutingSnapshot) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = Vec::with_capacity(256);
    bytes.push(CODEC_VERSION);
    bytes.extend_from_slice(&snapshot.routing_generation.get().to_be_bytes());
    write_string(&mut bytes, "source", snapshot.source.as_str())?;
    write_string(&mut bytes, "candidate", snapshot.candidate.as_str())?;
    let dimension_count = u16::try_from(snapshot.cohort.dimensions().len()).map_err(|_| {
        MigrationCodecError::Oversized {
            field: "cohort",
            max: usize::from(u16::MAX),
            actual: snapshot.cohort.dimensions().len(),
        }
    })?;
    bytes.extend_from_slice(&dimension_count.to_be_bytes());
    for dimension in snapshot.cohort.dimensions() {
        write_string(&mut bytes, "cohort_key", dimension.key())?;
        write_string(&mut bytes, "cohort_value", dimension.value())?;
    }
    match &snapshot.authority {
        RuntimeAuthority::Source(generation) => {
            bytes.push(1);
            write_string(&mut bytes, "authority_generation", generation.as_str())?;
        }
        RuntimeAuthority::Candidate(generation) => {
            bytes.push(2);
            write_string(&mut bytes, "authority_generation", generation.as_str())?;
        }
    }
    bytes.extend_from_slice(snapshot.contract_digest.as_bytes());
    bytes.extend_from_slice(snapshot.profile_digest.as_bytes());
    bytes.extend_from_slice(snapshot.config_digest.as_bytes());
    bytes.extend_from_slice(snapshot.fencing_token.as_bytes());
    bytes.push(match snapshot.rollback_disposition {
        RollbackDisposition::Eligible => 1,
        RollbackDisposition::Ineligible => 2,
    });
    bytes.extend_from_slice(&snapshot.committed_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one canonical routing snapshot.
pub fn decode_routing_snapshot(bytes: &[u8]) -> Result<RoutingSnapshot, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.read_u8()?;
    if version != CODEC_VERSION {
        return Err(MigrationCodecError::UnknownVersion { actual: version });
    }
    let routing_generation = RoutingGeneration::new(decoder.read_u64()?).map_err(|_| {
        MigrationCodecError::InvalidValue {
            field: "routing_generation",
        }
    })?;
    let source = runtime_generation(decoder.read_string("source")?, "source")?;
    let candidate = runtime_generation(decoder.read_string("candidate")?, "candidate")?;
    if source == candidate {
        return Err(MigrationCodecError::InvalidValue {
            field: "source_candidate",
        });
    }
    let dimension_count = usize::from(decoder.read_u16()?);
    let mut dimensions = Vec::with_capacity(dimension_count);
    for _ in 0..dimension_count {
        dimensions.push(
            CohortDimension::new(
                decoder.read_string("cohort_key")?,
                decoder.read_string("cohort_value")?,
            )
            .map_err(|_| MigrationCodecError::InvalidValue { field: "cohort" })?,
        );
    }
    let cohort = CohortSelector::new(dimensions)
        .map_err(|_| MigrationCodecError::InvalidValue { field: "cohort" })?;
    let authority_tag = decoder.read_u8()?;
    let authority_generation = runtime_generation(
        decoder.read_string("authority_generation")?,
        "authority_generation",
    )?;
    let authority = match authority_tag {
        1 if authority_generation == source => RuntimeAuthority::Source(authority_generation),
        2 if authority_generation == candidate => RuntimeAuthority::Candidate(authority_generation),
        1 | 2 => {
            return Err(MigrationCodecError::InvalidValue {
                field: "authority_generation",
            });
        }
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "authority",
                actual,
            });
        }
    };
    let contract_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let profile_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let config_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let fencing_token = FencingToken::new(decoder.read_array()?).map_err(|_| {
        MigrationCodecError::InvalidValue {
            field: "fencing_token",
        }
    })?;
    let rollback_disposition = match decoder.read_u8()? {
        1 => RollbackDisposition::Eligible,
        2 => RollbackDisposition::Ineligible,
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "rollback_disposition",
                actual,
            });
        }
    };
    let committed_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;

    Ok(RoutingSnapshot {
        routing_generation,
        source,
        candidate,
        cohort,
        authority,
        contract_digest,
        profile_digest,
        config_digest,
        fencing_token,
        rollback_disposition,
        committed_at,
    })
}

/// Encode one migration plan using migration codec version 1.
pub fn encode_migration_plan(plan: &MigrationPlan) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = Vec::with_capacity(512);
    bytes.push(CODEC_VERSION);
    write_string(&mut bytes, "plan_id", plan.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", plan.cycle_id.as_str())?;
    match &plan.cycle_kind {
        MigrationCycleKind::Forward => bytes.push(1),
        MigrationCycleKind::Rollback { parent_cycle_id } => {
            bytes.push(2);
            write_string(&mut bytes, "parent_cycle_id", parent_cycle_id.as_str())?;
        }
    }
    write_string(&mut bytes, "source", plan.source.as_str())?;
    write_string(&mut bytes, "candidate", plan.candidate.as_str())?;
    bytes.push(phase_tag(plan.phase));
    bytes.push(match plan.status {
        MigrationPlanStatus::Active => 1,
        MigrationPlanStatus::Retired => 2,
    });
    encode_routing_unit(&mut bytes, &plan.routing_unit)?;
    write_string(&mut bytes, "gate_policy", plan.gate_policy.as_str())?;
    bytes.extend_from_slice(&plan.plan_version.to_be_bytes());
    bytes.extend_from_slice(&plan.created_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one canonical migration plan.
pub fn decode_migration_plan(bytes: &[u8]) -> Result<MigrationPlan, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let cycle_kind = match decoder.read_u8()? {
        1 => MigrationCycleKind::Forward,
        2 => MigrationCycleKind::Rollback {
            parent_cycle_id: MigrationCycleId::new(decoder.read_string("parent_cycle_id")?)
                .map_err(|_| invalid("parent_cycle_id"))?,
        },
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "cycle_kind",
                actual,
            });
        }
    };
    let source = runtime_generation(decoder.read_string("source")?, "source")?;
    let candidate = runtime_generation(decoder.read_string("candidate")?, "candidate")?;
    if source == candidate {
        return Err(invalid("source_candidate"));
    }
    let phase = decode_phase(decoder.read_u8()?)?;
    let status = match decoder.read_u8()? {
        1 => MigrationPlanStatus::Active,
        2 => MigrationPlanStatus::Retired,
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "plan_status",
                actual,
            });
        }
    };
    let routing_unit = decode_routing_unit(&mut decoder)?;
    let gate_policy = GatePolicyRef::new(decoder.read_string("gate_policy")?)
        .map_err(|_| invalid("gate_policy"))?;
    let plan_version = decoder.read_u64()?;
    let created_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    Ok(MigrationPlan {
        plan_id,
        cycle_id,
        cycle_kind,
        source,
        candidate,
        phase,
        status,
        routing_unit,
        gate_policy,
        plan_version,
        created_at,
    })
}

/// Encode one immutable migration transition.
pub fn encode_migration_transition(
    transition: &MigrationTransition,
) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = vec![CODEC_VERSION];
    write_string(
        &mut bytes,
        "transition_id",
        transition.transition_id.as_str(),
    )?;
    write_string(&mut bytes, "plan_id", transition.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", transition.cycle_id.as_str())?;
    bytes.push(phase_tag(transition.from));
    bytes.push(phase_tag(transition.to));
    bytes.extend_from_slice(&transition.plan_version.to_be_bytes());
    bytes.extend_from_slice(&transition.occurred_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one immutable migration transition.
pub fn decode_migration_transition(
    bytes: &[u8],
) -> Result<MigrationTransition, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let transition_id = decoder.read_string("transition_id")?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let from = decode_phase(decoder.read_u8()?)?;
    let to = decode_phase(decoder.read_u8()?)?;
    let plan_version = decoder.read_u64()?;
    let occurred_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    Ok(MigrationTransition {
        transition_id,
        plan_id,
        cycle_id,
        from,
        to,
        plan_version,
        occurred_at,
    })
}
