/// Encode one immutable one-way migration report.
pub fn encode_migration_report(report: &MigrationReport) -> Result<Vec<u8>, MigrationCodecError> {
    if !report.has_valid_identity() {
        return Err(invalid("migration_report"));
    }
    let mut bytes = vec![CODEC_VERSION];
    encode_artifact_ref(&mut bytes, &report.report)?;
    write_string(&mut bytes, "plan_id", report.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", report.cycle_id.as_str())?;
    encode_artifact_ref(&mut bytes, &report.source_snapshot)?;
    bytes.extend_from_slice(&report.source_high_water.to_be_bytes());
    write_string(
        &mut bytes,
        "source_generation",
        report.source_generation.as_str(),
    )?;
    write_string(
        &mut bytes,
        "candidate_generation",
        report.candidate_generation.as_str(),
    )?;
    for count in [
        report.counts.imported,
        report.counts.skipped,
        report.counts.unsupported,
        report.counts.rejected,
        report.counts.unknown,
        report.counts.lossy,
        report.counts.ambiguous,
    ] {
        bytes.extend_from_slice(&count.to_be_bytes());
    }
    encode_artifact_ref(&mut bytes, &report.schema)?;
    encode_artifact_ref(&mut bytes, &report.mapping)?;
    encode_artifact_ref(&mut bytes, &report.profile)?;
    bytes.push(validation_tag(report.integrity));
    bytes.push(validation_tag(report.rebuild));
    match &report.disposition {
        ImportDisposition::Clean => bytes.push(1),
        ImportDisposition::ManualAuthorized(authorization) => {
            bytes.push(2);
            encode_artifact_ref(&mut bytes, authorization)?;
        }
    }
    bytes.extend_from_slice(&report.created_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one immutable one-way migration report.
pub fn decode_migration_report(bytes: &[u8]) -> Result<MigrationReport, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let report = decode_artifact_ref(&mut decoder, "report")?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let source_snapshot = decode_artifact_ref(&mut decoder, "source_snapshot")?;
    let source_high_water = decoder.read_u64()?;
    let source_generation = runtime_generation(
        decoder.read_string("source_generation")?,
        "source_generation",
    )?;
    let candidate_generation = runtime_generation(
        decoder.read_string("candidate_generation")?,
        "candidate_generation",
    )?;
    let counts = MigrationCounts {
        imported: decoder.read_u64()?,
        skipped: decoder.read_u64()?,
        unsupported: decoder.read_u64()?,
        rejected: decoder.read_u64()?,
        unknown: decoder.read_u64()?,
        lossy: decoder.read_u64()?,
        ambiguous: decoder.read_u64()?,
    };
    let schema = decode_artifact_ref(&mut decoder, "schema")?;
    let mapping = decode_artifact_ref(&mut decoder, "mapping")?;
    let profile = decode_artifact_ref(&mut decoder, "profile")?;
    let integrity = decode_validation(decoder.read_u8()?)?;
    let rebuild = decode_validation(decoder.read_u8()?)?;
    let disposition = match decoder.read_u8()? {
        1 => ImportDisposition::Clean,
        2 => ImportDisposition::ManualAuthorized(decode_artifact_ref(
            &mut decoder,
            "manual_authorization",
        )?),
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "import_disposition",
                actual,
            });
        }
    };
    let created_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    MigrationReport::new(MigrationReportFields {
        report,
        plan_id,
        cycle_id,
        source_snapshot,
        source_high_water,
        source_generation,
        candidate_generation,
        counts,
        schema,
        mapping,
        profile,
        integrity,
        rebuild,
        disposition,
        created_at,
    })
    .map_err(|_| invalid("migration_report"))
}

/// Encode one isolated rollback-cycle manifest.
pub fn encode_rollback_manifest(
    manifest: &RollbackManifest,
) -> Result<Vec<u8>, MigrationCodecError> {
    if !manifest.has_valid_identity() {
        return Err(invalid("rollback_manifest"));
    }
    let mut bytes = vec![CODEC_VERSION];
    encode_artifact_ref(&mut bytes, &manifest.manifest)?;
    write_string(&mut bytes, "plan_id", manifest.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", manifest.cycle_id.as_str())?;
    write_string(
        &mut bytes,
        "parent_plan_id",
        manifest.parent_plan_id.as_str(),
    )?;
    encode_routing_unit(&mut bytes, &manifest.routing_unit)?;
    bytes.extend_from_slice(&manifest.candidate_high_water.to_be_bytes());
    encode_artifact_ref(&mut bytes, &manifest.changed_state_inventory)?;
    encode_artifact_ref(&mut bytes, &manifest.reconciliation_report)?;
    match &manifest.reverse_migration_contract {
        Some(contract) => {
            bytes.push(1);
            encode_artifact_ref(&mut bytes, contract)?;
        }
        None => bytes.push(0),
    }
    bytes.extend_from_slice(&manifest.expected_routing_generation.get().to_be_bytes());
    encode_artifact_ref(&mut bytes, &manifest.operator_authorization)?;
    bytes.extend_from_slice(&manifest.created_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one isolated rollback-cycle manifest.
pub fn decode_rollback_manifest(bytes: &[u8]) -> Result<RollbackManifest, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let manifest = decode_artifact_ref(&mut decoder, "manifest")?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let parent_plan_id = MigrationPlanId::new(decoder.read_string("parent_plan_id")?)
        .map_err(|_| invalid("parent_plan_id"))?;
    let routing_unit = decode_routing_unit(&mut decoder)?;
    let candidate_high_water = decoder.read_u64()?;
    let changed_state_inventory = decode_artifact_ref(&mut decoder, "changed_state_inventory")?;
    let reconciliation_report = decode_artifact_ref(&mut decoder, "reconciliation_report")?;
    let reverse_migration_contract = match decoder.read_u8()? {
        0 => None,
        1 => Some(decode_artifact_ref(
            &mut decoder,
            "reverse_migration_contract",
        )?),
        actual => {
            return Err(MigrationCodecError::UnknownTag {
                field: "reverse_migration_contract",
                actual,
            });
        }
    };
    let expected_routing_generation =
        RoutingGeneration::new(decoder.read_u64()?).map_err(|_| invalid("routing_generation"))?;
    let operator_authorization = decode_artifact_ref(&mut decoder, "operator_authorization")?;
    let created_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    let manifest = RollbackManifest {
        manifest,
        plan_id,
        cycle_id,
        parent_plan_id,
        routing_unit,
        candidate_high_water,
        changed_state_inventory,
        reconciliation_report,
        reverse_migration_contract,
        expected_routing_generation,
        operator_authorization,
        created_at,
    };
    if !manifest.has_valid_identity() {
        return Err(invalid("rollback_manifest"));
    }
    Ok(manifest)
}

/// Encode one final source-retirement manifest.
pub fn encode_retirement_manifest(
    manifest: &RetirementManifest,
) -> Result<Vec<u8>, MigrationCodecError> {
    if !manifest.has_valid_identity() {
        return Err(invalid("retirement_manifest"));
    }
    let mut bytes = vec![RETIREMENT_MANIFEST_CODEC_VERSION];
    encode_artifact_ref(&mut bytes, &manifest.manifest)?;
    write_string(&mut bytes, "plan_id", manifest.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", manifest.cycle_id.as_str())?;
    encode_artifact_ref(&mut bytes, &manifest.final_drain_report)?;
    bytes.extend_from_slice(manifest.reference_inventory_digest.as_bytes());
    encode_artifact_ref(&mut bytes, &manifest.platform_verification_set)?;
    encode_artifact_ref(&mut bytes, &manifest.closed_windows_evidence)?;
    encode_artifact_ref(&mut bytes, &manifest.disabled_legacy_authority)?;
    encode_artifact_ref(&mut bytes, &manifest.final_audit)?;
    encode_artifact_ref(&mut bytes, &manifest.removal_diff)?;
    encode_artifact_ref(&mut bytes, &manifest.removal_suite)?;
    bytes.extend_from_slice(&manifest.retention_until.as_unix_micros().to_be_bytes());
    encode_artifact_ref(&mut bytes, &manifest.operator_authorization)?;
    bytes.extend_from_slice(&manifest.created_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one final source-retirement manifest.
pub fn decode_retirement_manifest(bytes: &[u8]) -> Result<RetirementManifest, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.read_u8()?;
    if version != RETIREMENT_MANIFEST_CODEC_VERSION {
        return Err(MigrationCodecError::UnknownVersion { actual: version });
    }
    let manifest = decode_artifact_ref(&mut decoder, "manifest")?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let final_drain_report = decode_artifact_ref(&mut decoder, "final_drain_report")?;
    let reference_inventory_digest = ArtifactDigest::from_bytes(decoder.read_array()?);
    let platform_verification_set = decode_artifact_ref(&mut decoder, "platform_verification_set")?;
    let closed_windows_evidence = decode_artifact_ref(&mut decoder, "closed_windows_evidence")?;
    let disabled_legacy_authority = decode_artifact_ref(&mut decoder, "disabled_legacy_authority")?;
    let final_audit = decode_artifact_ref(&mut decoder, "final_audit")?;
    let removal_diff = decode_artifact_ref(&mut decoder, "removal_diff")?;
    let removal_suite = decode_artifact_ref(&mut decoder, "removal_suite")?;
    let retention_until = Timestamp::from_unix_micros(decoder.read_i64()?);
    let operator_authorization = decode_artifact_ref(&mut decoder, "operator_authorization")?;
    let created_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    let manifest = RetirementManifest {
        manifest,
        plan_id,
        cycle_id,
        final_drain_report,
        reference_inventory_digest,
        platform_verification_set,
        closed_windows_evidence,
        disabled_legacy_authority,
        final_audit,
        removal_diff,
        removal_suite,
        retention_until,
        operator_authorization,
        created_at,
    };
    if !manifest.has_valid_identity() {
        return Err(invalid("retirement_manifest"));
    }
    Ok(manifest)
}
