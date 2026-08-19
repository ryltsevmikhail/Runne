/// Encode immutable migration evidence.
pub fn encode_migration_evidence(
    evidence: &MigrationEvidence,
) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = vec![CODEC_VERSION];
    match evidence {
        MigrationEvidence::Baseline {
            source_sha,
            inventory_digest,
            fixture_digest,
        } => {
            bytes.push(1);
            write_string(&mut bytes, "source_sha", source_sha)?;
            bytes.extend_from_slice(inventory_digest.as_bytes());
            bytes.extend_from_slice(fixture_digest.as_bytes());
        }
        MigrationEvidence::Foundation {
            contract_digest,
            store_integrity_digest,
            deterministic_test_digest,
        } => {
            bytes.push(2);
            bytes.extend_from_slice(contract_digest.as_bytes());
            bytes.extend_from_slice(store_integrity_digest.as_bytes());
            bytes.extend_from_slice(deterministic_test_digest.as_bytes());
        }
        MigrationEvidence::ReadOnlyParity {
            import_report_digest,
            completeness_digest,
            canonical_mutation_count,
        } => {
            bytes.push(3);
            bytes.extend_from_slice(import_report_digest.as_bytes());
            bytes.extend_from_slice(completeness_digest.as_bytes());
            bytes.extend_from_slice(&canonical_mutation_count.to_be_bytes());
        }
        MigrationEvidence::SimulatedShadow {
            semantic_diff_digest,
            canonical_write_count,
            external_effect_count,
            client_acknowledgement_count,
        } => {
            bytes.push(4);
            bytes.extend_from_slice(semantic_diff_digest.as_bytes());
            bytes.extend_from_slice(&canonical_write_count.to_be_bytes());
            bytes.extend_from_slice(&external_effect_count.to_be_bytes());
            bytes.extend_from_slice(&client_acknowledgement_count.to_be_bytes());
        }
        MigrationEvidence::ProductionGate(gate) => {
            bytes.push(5);
            encode_gate_evidence(&mut bytes, gate)?;
        }
    }
    Ok(bytes)
}

/// Decode immutable migration evidence.
pub fn decode_migration_evidence(bytes: &[u8]) -> Result<MigrationEvidence, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let evidence = match decoder.read_u8()? {
        1 => MigrationEvidence::Baseline {
            source_sha: decoder.read_string("source_sha")?,
            inventory_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
            fixture_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
        },
        2 => MigrationEvidence::Foundation {
            contract_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
            store_integrity_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
            deterministic_test_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
        },
        3 => MigrationEvidence::ReadOnlyParity {
            import_report_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
            completeness_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
            canonical_mutation_count: decoder.read_u64()?,
        },
        4 => MigrationEvidence::SimulatedShadow {
            semantic_diff_digest: ArtifactDigest::from_bytes(decoder.read_array()?),
            canonical_write_count: decoder.read_u64()?,
            external_effect_count: decoder.read_u64()?,
            client_acknowledgement_count: decoder.read_u64()?,
        },
        5 => MigrationEvidence::ProductionGate(decode_gate_evidence(&mut decoder)?),
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "migration_evidence",
                actual,
            });
        }
    };
    decoder.finish()?;
    Ok(evidence)
}

/// Encode one command outcome stored in an idempotency receipt.
pub fn encode_migration_outcome(
    outcome: &MigrationCommandOutcome,
) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = vec![CODEC_VERSION];
    write_blob(&mut bytes, "plan", &encode_migration_plan(&outcome.plan)?)?;
    match &outcome.routing_snapshot {
        Some(snapshot) => {
            bytes.push(1);
            write_blob(
                &mut bytes,
                "routing_snapshot",
                &encode_routing_snapshot(snapshot)?,
            )?;
        }
        None => bytes.push(0),
    }
    write_string(&mut bytes, "transition_id", &outcome.transition_id)?;
    Ok(bytes)
}

/// Decode one command outcome from an idempotency receipt.
pub fn decode_migration_outcome(
    bytes: &[u8],
) -> Result<MigrationCommandOutcome, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let plan = decode_migration_plan(decoder.read_blob("plan")?)?;
    let routing_snapshot = match decoder.read_u8()? {
        0 => None,
        1 => Some(decode_routing_snapshot(
            decoder.read_blob("routing_snapshot")?,
        )?),
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "routing_snapshot_option",
                actual,
            });
        }
    };
    let transition_id = decoder.read_string("transition_id")?;
    decoder.finish()?;
    Ok(MigrationCommandOutcome {
        plan,
        routing_snapshot,
        transition_id,
    })
}

/// Encode one canonical audit record.
pub fn encode_migration_audit(
    audit: &MigrationAuditRecord,
) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = vec![CODEC_VERSION];
    bytes.extend_from_slice(audit.record_id.as_bytes());
    write_string(&mut bytes, "plan_id", audit.plan_id.as_str())?;
    bytes.extend_from_slice(audit.command_id.as_bytes());
    write_string(&mut bytes, "operator_id", audit.operator_id.as_str())?;
    bytes.push(audit_action_tag(audit.action));
    bytes.extend_from_slice(&audit.recorded_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Encode one immutable runtime binding.
pub fn encode_runtime_binding(binding: &RuntimeBinding) -> Result<Vec<u8>, MigrationCodecError> {
    let mut bytes = vec![CODEC_VERSION];
    let (aggregate_tag, aggregate_bytes) = aggregate_parts(&binding.aggregate_id);
    bytes.push(aggregate_tag);
    bytes.extend_from_slice(aggregate_bytes);
    match &binding.authority {
        RuntimeAuthority::Source(generation) => {
            bytes.push(1);
            write_string(&mut bytes, "authority_generation", generation.as_str())?;
        }
        RuntimeAuthority::Candidate(generation) => {
            bytes.push(2);
            write_string(&mut bytes, "authority_generation", generation.as_str())?;
        }
    }
    write_string(
        &mut bytes,
        "runtime_generation",
        binding.runtime_generation.as_str(),
    )?;
    bytes.extend_from_slice(&binding.routing_generation.get().to_be_bytes());
    bytes.extend_from_slice(binding.fencing_token.as_bytes());
    bytes.extend_from_slice(&binding.bound_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one immutable runtime binding.
pub fn decode_runtime_binding(bytes: &[u8]) -> Result<RuntimeBinding, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let aggregate_tag = decoder.read_u8()?;
    let aggregate_bytes = decoder.read_array::<16>()?;
    let aggregate_id = match aggregate_tag {
        1 => AggregateId::TaskRun(
            TaskRunId::from_bytes(aggregate_bytes)
                .to_string()
                .parse()
                .map_err(|_| invalid("aggregate_id"))?,
        ),
        2 => AggregateId::Conversation(
            ConversationId::from_bytes(aggregate_bytes)
                .to_string()
                .parse()
                .map_err(|_| invalid("aggregate_id"))?,
        ),
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "aggregate_type",
                actual,
            });
        }
    };
    let authority_tag = decoder.read_u8()?;
    let authority_generation = runtime_generation(
        decoder.read_string("authority_generation")?,
        "authority_generation",
    )?;
    let authority = match authority_tag {
        1 => RuntimeAuthority::Source(authority_generation),
        2 => RuntimeAuthority::Candidate(authority_generation),
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "authority",
                actual,
            });
        }
    };
    let runtime_generation = runtime_generation(
        decoder.read_string("runtime_generation")?,
        "runtime_generation",
    )?;
    let routing_generation =
        RoutingGeneration::new(decoder.read_u64()?).map_err(|_| invalid("routing_generation"))?;
    let fencing_token =
        FencingToken::new(decoder.read_array()?).map_err(|_| invalid("fencing_token"))?;
    let bound_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;

    RuntimeBinding::new(
        aggregate_id,
        authority,
        runtime_generation,
        routing_generation,
        fencing_token,
        bound_at,
    )
    .map_err(|_| invalid("runtime_binding"))
}
