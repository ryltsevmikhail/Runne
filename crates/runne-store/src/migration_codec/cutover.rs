/// Encode one immutable cutover preparation manifest.
pub fn encode_cutover_manifest(manifest: &CutoverManifest) -> Result<Vec<u8>, MigrationCodecError> {
    if !manifest.has_valid_identity() {
        return Err(invalid("cutover_manifest"));
    }
    let mut bytes = vec![CUTOVER_MANIFEST_CODEC_VERSION];
    encode_artifact_ref(
        &mut bytes,
        &ArtifactRef {
            reference: manifest.manifest_ref.clone(),
            digest: manifest.manifest_digest,
        },
    )?;
    write_string(&mut bytes, "plan_id", manifest.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", manifest.cycle_id.as_str())?;
    bytes.push(cutover_intent_tag(manifest.intent));
    encode_cutover_policy(&mut bytes, &manifest.rollout_policy)?;
    encode_routing_unit(&mut bytes, &manifest.routing_unit)?;
    encode_artifact_ref(&mut bytes, &manifest.source_release)?;
    write_string(
        &mut bytes,
        "source_generation",
        manifest.source_generation.as_str(),
    )?;
    encode_artifact_ref(&mut bytes, &manifest.candidate_release)?;
    write_string(
        &mut bytes,
        "candidate_generation",
        manifest.candidate_generation.as_str(),
    )?;
    encode_artifact_ref(
        &mut bytes,
        &ArtifactRef {
            reference: manifest.evidence_set_ref.clone(),
            digest: manifest.evidence_set_digest,
        },
    )?;
    encode_artifact_ref(&mut bytes, &manifest.import_report)?;
    encode_artifact_ref(&mut bytes, &manifest.drain_report)?;
    encode_artifact_ref(&mut bytes, &manifest.candidate_validation)?;
    bytes.extend_from_slice(&manifest.source_high_water.to_be_bytes());
    bytes.extend_from_slice(&manifest.expected_routing_generation.get().to_be_bytes());
    encode_rollback_policy(&mut bytes, &manifest.rollback_policy)?;
    bytes.extend_from_slice(&manifest.retention_until.as_unix_micros().to_be_bytes());
    encode_artifact_ref(&mut bytes, &manifest.operator_authorization)?;
    write_string(
        &mut bytes,
        "prepared_transition_id",
        &manifest.prepared_transition_id,
    )?;
    bytes.extend_from_slice(&manifest.expected_plan_version.to_be_bytes());
    bytes.extend_from_slice(&manifest.plan_version.to_be_bytes());
    bytes.extend_from_slice(&manifest.prepared_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one immutable cutover preparation manifest.
pub fn decode_cutover_manifest(bytes: &[u8]) -> Result<CutoverManifest, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.read_u8()?;
    if version != CUTOVER_MANIFEST_CODEC_VERSION {
        return Err(MigrationCodecError::UnknownVersion { actual: version });
    }
    let manifest_identity = decode_artifact_ref(&mut decoder, "manifest")?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let intent = decode_cutover_intent(decoder.read_u8()?)?;
    let rollout_policy = decode_cutover_policy(&mut decoder)?;
    let routing_unit = decode_routing_unit(&mut decoder)?;
    let source_release = decode_artifact_ref(&mut decoder, "source_release")?;
    let source_generation = runtime_generation(
        decoder.read_string("source_generation")?,
        "source_generation",
    )?;
    let candidate_release = decode_artifact_ref(&mut decoder, "candidate_release")?;
    let candidate_generation = runtime_generation(
        decoder.read_string("candidate_generation")?,
        "candidate_generation",
    )?;
    let frozen_evidence_set = decode_artifact_ref(&mut decoder, "evidence_set")?;
    let import_report = decode_artifact_ref(&mut decoder, "import_report")?;
    let drain_report = decode_artifact_ref(&mut decoder, "drain_report")?;
    let candidate_validation = decode_artifact_ref(&mut decoder, "candidate_validation")?;
    let source_high_water = decoder.read_u64()?;
    let expected_routing_generation =
        RoutingGeneration::new(decoder.read_u64()?).map_err(|_| invalid("routing_generation"))?;
    let rollback_policy = decode_rollback_policy(&mut decoder)?;
    let retention_until = Timestamp::from_unix_micros(decoder.read_i64()?);
    let operator_authorization = decode_artifact_ref(&mut decoder, "operator_authorization")?;
    let prepared_transition_id = decoder.read_string("prepared_transition_id")?;
    let expected_plan_version = decoder.read_u64()?;
    let plan_version = decoder.read_u64()?;
    let prepared_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    let manifest = CutoverManifest {
        manifest_digest: manifest_identity.digest,
        manifest_ref: manifest_identity.reference,
        plan_id,
        cycle_id,
        intent,
        rollout_policy,
        routing_unit,
        source_release,
        source_generation,
        candidate_release,
        candidate_generation,
        evidence_set_digest: frozen_evidence_set.digest,
        evidence_set_ref: frozen_evidence_set.reference,
        import_report,
        drain_report,
        candidate_validation,
        source_high_water,
        expected_routing_generation,
        rollback_policy,
        retention_until,
        operator_authorization,
        prepared_transition_id,
        expected_plan_version,
        plan_version,
        prepared_at,
    };
    if !manifest.has_valid_identity() {
        return Err(invalid("cutover_manifest"));
    }
    Ok(manifest)
}
