fn encode_routing_unit(bytes: &mut Vec<u8>, unit: &RoutingUnit) -> Result<(), MigrationCodecError> {
    write_string(bytes, "deployment", unit.deployment.as_str())?;
    write_cohort(bytes, &unit.cohort)?;
    write_string(
        bytes,
        "profile_id",
        unit.feature_profile.profile_id.as_str(),
    )?;
    bytes.extend_from_slice(&unit.feature_profile.profile_revision.to_be_bytes());
    bytes.extend_from_slice(unit.feature_profile.profile_digest.as_bytes());
    bytes.extend_from_slice(unit.contract_digest.as_bytes());
    bytes.extend_from_slice(unit.schema_digest.as_bytes());
    bytes.extend_from_slice(unit.config_digest.as_bytes());
    Ok(())
}

fn decode_routing_unit(decoder: &mut Decoder<'_>) -> Result<RoutingUnit, MigrationCodecError> {
    let deployment =
        DeploymentId::new(decoder.read_string("deployment")?).map_err(|_| invalid("deployment"))?;
    let cohort = read_cohort(decoder)?;
    let profile_id = decoder.read_string("profile_id")?;
    let profile_revision = decoder.read_u16()?;
    let profile_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let feature_profile = FeatureProfileRef::new(profile_id, profile_revision, profile_digest)
        .map_err(|_| invalid("feature_profile"))?;
    Ok(RoutingUnit {
        deployment,
        cohort,
        feature_profile,
        contract_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
        schema_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
        config_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
    })
}

fn encode_gate_evidence(
    bytes: &mut Vec<u8>,
    gate: &GateEvidence,
) -> Result<(), MigrationCodecError> {
    write_string(bytes, "gate_id", gate.gate_id.as_str())?;
    bytes.extend_from_slice(&gate.gate_revision.to_be_bytes());
    bytes.push(gate.family as u8);
    write_string(bytes, "source_generation", gate.source_generation.as_str())?;
    write_string(
        bytes,
        "candidate_generation",
        gate.candidate_generation.as_str(),
    )?;
    write_cohort(bytes, &gate.cohort)?;
    bytes.extend_from_slice(gate.contract_digest.as_bytes());
    bytes.extend_from_slice(gate.profile_digest.as_bytes());
    bytes.extend_from_slice(gate.config_digest.as_bytes());
    bytes.extend_from_slice(&gate.measured_at.as_unix_micros().to_be_bytes());
    bytes.extend_from_slice(&gate.valid_until.as_unix_micros().to_be_bytes());
    match gate.status {
        GateStatus::Passed => bytes.push(1),
        GateStatus::Failed { code } => {
            bytes.push(2);
            bytes.push(gate_failure_tag(code));
        }
        GateStatus::Revoked { reason } => {
            bytes.push(3);
            bytes.push(gate_revocation_tag(reason));
        }
    }
    bytes.extend_from_slice(gate.evidence_digest.as_bytes());
    Ok(())
}

fn decode_gate_evidence(decoder: &mut Decoder<'_>) -> Result<GateEvidence, MigrationCodecError> {
    let gate_id = GateId::new(decoder.read_string("gate_id")?).map_err(|_| invalid("gate_id"))?;
    let gate_revision = decoder.read_u16()?;
    if gate_revision == 0 {
        return Err(invalid("gate_revision"));
    }
    let family = decode_gate_family(decoder.read_u8()?)?;
    let source_generation = runtime_generation(
        decoder.read_string("source_generation")?,
        "source_generation",
    )?;
    let candidate_generation = runtime_generation(
        decoder.read_string("candidate_generation")?,
        "candidate_generation",
    )?;
    let cohort = read_cohort(decoder)?;
    let contract_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let profile_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let config_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let measured_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    let valid_until = Timestamp::from_unix_micros(decoder.read_i64()?);
    let status = match decoder.read_u8()? {
        1 => GateStatus::Passed,
        2 => GateStatus::Failed {
            code: decode_gate_failure(decoder.read_u8()?)?,
        },
        3 => GateStatus::Revoked {
            reason: decode_gate_revocation(decoder.read_u8()?)?,
        },
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "gate_status",
                actual,
            });
        }
    };
    let evidence_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    Ok(GateEvidence {
        gate_id,
        gate_revision,
        family,
        source_generation,
        candidate_generation,
        cohort,
        contract_digest,
        profile_digest,
        config_digest,
        measured_at,
        valid_until,
        status,
        evidence_digest,
    })
}

fn write_cohort(bytes: &mut Vec<u8>, cohort: &CohortSelector) -> Result<(), MigrationCodecError> {
    let count =
        u16::try_from(cohort.dimensions().len()).map_err(|_| MigrationCodecError::Oversized {
            field: "cohort",
            max: usize::from(u16::MAX),
            actual: cohort.dimensions().len(),
        })?;
    bytes.extend_from_slice(&count.to_be_bytes());
    for dimension in cohort.dimensions() {
        write_string(bytes, "cohort_key", dimension.key())?;
        write_string(bytes, "cohort_value", dimension.value())?;
    }
    Ok(())
}

fn read_cohort(decoder: &mut Decoder<'_>) -> Result<CohortSelector, MigrationCodecError> {
    let count = usize::from(decoder.read_u16()?);
    let mut dimensions = Vec::with_capacity(count);
    for _ in 0..count {
        dimensions.push(
            CohortDimension::new(
                decoder.read_string("cohort_key")?,
                decoder.read_string("cohort_value")?,
            )
            .map_err(|_| invalid("cohort"))?,
        );
    }
    CohortSelector::new(dimensions).map_err(|_| invalid("cohort"))
}

fn aggregate_parts(aggregate_id: &AggregateId) -> (u8, &[u8; 16]) {
    match aggregate_id {
        AggregateId::TaskRun(id) => (1, id.as_bytes()),
        AggregateId::Conversation(id) => (2, id.as_bytes()),
        AggregateId::Workspace(id) => (3, id.as_bytes()),
    }
}

fn encode_artifact_ref(
    bytes: &mut Vec<u8>,
    artifact: &ArtifactRef,
) -> Result<(), MigrationCodecError> {
    if !artifact.is_valid() {
        return Err(invalid("artifact_ref"));
    }
    write_string(bytes, "artifact_ref", &artifact.reference)?;
    bytes.extend_from_slice(artifact.digest.as_bytes());
    Ok(())
}

fn decode_artifact_ref(
    decoder: &mut Decoder<'_>,
    field: &'static str,
) -> Result<ArtifactRef, MigrationCodecError> {
    ArtifactRef::new(
        decoder.read_string(field)?,
        ArtifactDigest::from_bytes(decoder.read_array()?),
    )
    .map_err(|_| invalid(field))
}

fn encode_cutover_policy(
    bytes: &mut Vec<u8>,
    policy: &CutoverPolicy,
) -> Result<(), MigrationCodecError> {
    match policy {
        CutoverPolicy::InternalCanary(policy) => {
            bytes.push(1);
            write_cohort(bytes, &policy.target_cohort)?;
            bytes.extend_from_slice(&policy.admission_limit.to_be_bytes());
        }
        CutoverPolicy::CohortExpansion(step) => {
            bytes.push(2);
            bytes.extend_from_slice(&step.previous_routing_generation.get().to_be_bytes());
            write_cohort(bytes, &step.target_cohort)?;
            bytes.extend_from_slice(&step.admission_limit.to_be_bytes());
            bytes.extend_from_slice(&step.observation_window.as_secs().to_be_bytes());
            bytes.extend_from_slice(&step.observation_window.subsec_nanos().to_be_bytes());
            bytes.extend_from_slice(&step.observed_from.as_unix_micros().to_be_bytes());
            bytes.extend_from_slice(&step.observed_until.as_unix_micros().to_be_bytes());
            write_string(
                bytes,
                "required_gate_policy",
                step.required_gate_policy.as_str(),
            )?;
        }
        CutoverPolicy::DefaultNative(policy) => {
            bytes.push(3);
            match policy {
                PreDispatchFallbackPolicy::Disabled => bytes.push(0),
                PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance { source_profile } => {
                    bytes.push(1);
                    write_string(bytes, "source_profile_id", &source_profile.profile_id)?;
                    bytes.extend_from_slice(&source_profile.profile_revision.to_be_bytes());
                    bytes.extend_from_slice(source_profile.profile_digest.as_bytes());
                }
            }
        }
    }
    Ok(())
}

fn decode_cutover_policy(decoder: &mut Decoder<'_>) -> Result<CutoverPolicy, MigrationCodecError> {
    match decoder.read_u8()? {
        1 => Ok(CutoverPolicy::InternalCanary(
            CanaryPolicy::new(read_cohort(decoder)?, decoder.read_u32()?)
                .map_err(|_| invalid("canary_policy"))?,
        )),
        2 => {
            let previous_routing_generation = RoutingGeneration::new(decoder.read_u64()?)
                .map_err(|_| invalid("previous_routing_generation"))?;
            let target_cohort = read_cohort(decoder)?;
            let admission_limit = decoder.read_u32()?;
            let observation_secs = decoder.read_u64()?;
            let observation_nanos = decoder.read_u32()?;
            if observation_nanos >= 1_000_000_000 {
                return Err(invalid("observation_window"));
            }
            let observed_from = Timestamp::from_unix_micros(decoder.read_i64()?);
            let observed_until = Timestamp::from_unix_micros(decoder.read_i64()?);
            let required_gate_policy =
                GatePolicyRef::new(decoder.read_string("required_gate_policy")?)
                    .map_err(|_| invalid("required_gate_policy"))?;
            Ok(CutoverPolicy::CohortExpansion(
                RolloutStep::new(
                    previous_routing_generation,
                    target_cohort,
                    admission_limit,
                    Duration::new(observation_secs, observation_nanos),
                    observed_from,
                    observed_until,
                    required_gate_policy,
                )
                .map_err(|_| invalid("rollout_step"))?,
            ))
        }
        3 => match decoder.read_u8()? {
            0 => Ok(CutoverPolicy::DefaultNative(
                PreDispatchFallbackPolicy::Disabled,
            )),
            1 => Ok(CutoverPolicy::DefaultNative(
                PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
                    source_profile: FeatureProfileRef::new(
                        decoder.read_string("source_profile_id")?,
                        decoder.read_u16()?,
                        ArtifactDigest::from_bytes(decoder.read_array()?),
                    )
                    .map_err(|_| invalid("source_profile"))?,
                },
            )),
            actual => Err(MigrationCodecError::UnknownTag {
                field: "pre_dispatch_fallback_policy",
                actual,
            }),
        },
        actual => Err(MigrationCodecError::UnknownTag {
            field: "cutover_policy",
            actual,
        }),
    }
}
