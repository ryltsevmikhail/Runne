//! Versioned canonical codecs for migration control-plane artifacts.

use core::fmt;

use gocode_application::migration::{
    gates::{GateEvidence, GateFailureCode, GateRevocationReason, GateStatus, MigrationEvidence},
    manifests::{
        ArtifactRef, ArtifactValidation, CutoverManifest, ImportDisposition, MigrationCounts,
        MigrationReport, MigrationReportFields, RetirementManifest, RollbackManifest,
        RollbackPolicy,
    },
    ports::{
        CutoverIntent, MigrationAuditAction, MigrationAuditRecord, MigrationCommandOutcome,
        MigrationTransition,
    },
    state::{MigrationCycleKind, MigrationPhase, MigrationPlan, MigrationPlanStatus},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, GateFamily, GateId, GatePolicyRef, MigrationCycleId, MigrationPlanId,
        MigrationValueError, RollbackDisposition, RoutingGeneration, RoutingSnapshot, RoutingUnit,
        RuntimeAuthority, RuntimeBinding, RuntimeGenerationRef,
    },
};
use gocode_domain::{
    id::{AggregateId, ConversationId, TaskRunId},
    timestamp::Timestamp,
};

const CODEC_VERSION: u8 = 1;
const CUTOVER_MANIFEST_CODEC_VERSION: u8 = 2;

/// Fail-closed migration codec errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationCodecError {
    /// Unsupported leading codec version.
    UnknownVersion {
        /// Version read from durable bytes.
        actual: u8,
    },
    /// Closed enum tag is unknown.
    UnknownTag {
        /// Field whose tag was invalid.
        field: &'static str,
        /// Unknown tag.
        actual: u8,
    },
    /// Durable bytes ended before the value was complete.
    Truncated,
    /// Bytes remained after one canonical value.
    TrailingBytes {
        /// Number of bytes not consumed.
        remaining: usize,
    },
    /// A length-prefixed value exceeds its bound.
    Oversized {
        /// Field whose value was oversized.
        field: &'static str,
        /// Maximum number of bytes.
        max: usize,
        /// Actual number of bytes.
        actual: usize,
    },
    /// A string is not valid UTF-8.
    InvalidUtf8 {
        /// Field containing invalid UTF-8.
        field: &'static str,
    },
    /// Decoded values violate the application value contract.
    InvalidValue {
        /// Field whose value is invalid.
        field: &'static str,
    },
}

impl fmt::Display for MigrationCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for MigrationCodecError {}

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
    let mut bytes = vec![CODEC_VERSION];
    encode_artifact_ref(&mut bytes, &manifest.manifest)?;
    write_string(&mut bytes, "plan_id", manifest.plan_id.as_str())?;
    write_string(&mut bytes, "cycle_id", manifest.cycle_id.as_str())?;
    encode_artifact_ref(&mut bytes, &manifest.final_drain_report)?;
    encode_artifact_ref(&mut bytes, &manifest.final_audit)?;
    encode_artifact_ref(&mut bytes, &manifest.removal_diff)?;
    bytes.extend_from_slice(&manifest.retention_until.as_unix_micros().to_be_bytes());
    encode_artifact_ref(&mut bytes, &manifest.operator_authorization)?;
    bytes.extend_from_slice(&manifest.created_at.as_unix_micros().to_be_bytes());
    Ok(bytes)
}

/// Decode one final source-retirement manifest.
pub fn decode_retirement_manifest(bytes: &[u8]) -> Result<RetirementManifest, MigrationCodecError> {
    let mut decoder = versioned_decoder(bytes)?;
    let manifest = decode_artifact_ref(&mut decoder, "manifest")?;
    let plan_id =
        MigrationPlanId::new(decoder.read_string("plan_id")?).map_err(|_| invalid("plan_id"))?;
    let cycle_id =
        MigrationCycleId::new(decoder.read_string("cycle_id")?).map_err(|_| invalid("cycle_id"))?;
    let final_drain_report = decode_artifact_ref(&mut decoder, "final_drain_report")?;
    let final_audit = decode_artifact_ref(&mut decoder, "final_audit")?;
    let removal_diff = decode_artifact_ref(&mut decoder, "removal_diff")?;
    let retention_until = Timestamp::from_unix_micros(decoder.read_i64()?);
    let operator_authorization = decode_artifact_ref(&mut decoder, "operator_authorization")?;
    let created_at = Timestamp::from_unix_micros(decoder.read_i64()?);
    decoder.finish()?;
    let manifest = RetirementManifest {
        manifest,
        plan_id,
        cycle_id,
        final_drain_report,
        final_audit,
        removal_diff,
        retention_until,
        operator_authorization,
        created_at,
    };
    if !manifest.has_valid_identity() {
        return Err(invalid("retirement_manifest"));
    }
    Ok(manifest)
}

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

fn validation_tag(validation: ArtifactValidation) -> u8 {
    match validation {
        ArtifactValidation::Passed => 1,
        ArtifactValidation::Failed => 2,
    }
}

fn decode_validation(actual: u8) -> Result<ArtifactValidation, MigrationCodecError> {
    match actual {
        1 => Ok(ArtifactValidation::Passed),
        2 => Ok(ArtifactValidation::Failed),
        actual => Err(MigrationCodecError::UnknownTag {
            field: "artifact_validation",
            actual,
        }),
    }
}

fn encode_rollback_policy(
    bytes: &mut Vec<u8>,
    policy: &RollbackPolicy,
) -> Result<(), MigrationCodecError> {
    match policy {
        RollbackPolicy::BeforeCandidateWrites => bytes.push(1),
        RollbackPolicy::ReverseMigrationRequired(contract) => {
            bytes.push(2);
            encode_artifact_ref(bytes, contract)?;
        }
        RollbackPolicy::ManualOnly => bytes.push(3),
    }
    Ok(())
}

fn decode_rollback_policy(
    decoder: &mut Decoder<'_>,
) -> Result<RollbackPolicy, MigrationCodecError> {
    match decoder.read_u8()? {
        1 => Ok(RollbackPolicy::BeforeCandidateWrites),
        2 => Ok(RollbackPolicy::ReverseMigrationRequired(
            decode_artifact_ref(decoder, "reverse_migration_contract")?,
        )),
        3 => Ok(RollbackPolicy::ManualOnly),
        actual => Err(MigrationCodecError::UnknownTag {
            field: "rollback_policy",
            actual,
        }),
    }
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

fn decode_phase(tag: u8) -> Result<MigrationPhase, MigrationCodecError> {
    match tag {
        0 => Ok(MigrationPhase::Baseline),
        1 => Ok(MigrationPhase::Foundation),
        2 => Ok(MigrationPhase::ReadOnlyParity),
        3 => Ok(MigrationPhase::SimulatedShadow),
        4 => Ok(MigrationPhase::InternalCanary),
        5 => Ok(MigrationPhase::CohortRollout),
        6 => Ok(MigrationPhase::DefaultNative),
        7 => Ok(MigrationPhase::DrainDeprecate),
        8 => Ok(MigrationPhase::Retired),
        actual => Err(MigrationCodecError::UnknownTag {
            field: "phase",
            actual,
        }),
    }
}

fn decode_gate_family(tag: u8) -> Result<GateFamily, MigrationCodecError> {
    GateFamily::ALL
        .into_iter()
        .find(|family| *family as u8 == tag)
        .ok_or(MigrationCodecError::UnknownTag {
            field: "gate_family",
            actual: tag,
        })
}

fn gate_failure_tag(code: GateFailureCode) -> u8 {
    match code {
        GateFailureCode::Integrity => 1,
        GateFailureCode::Unavailable => 2,
        GateFailureCode::ScopeMismatch => 3,
        GateFailureCode::PolicyDenied => 4,
        GateFailureCode::Timeout => 5,
        GateFailureCode::Capacity => 6,
        GateFailureCode::Privacy => 7,
        GateFailureCode::UnresolvedEffect => 8,
    }
}

fn decode_gate_failure(tag: u8) -> Result<GateFailureCode, MigrationCodecError> {
    match tag {
        1 => Ok(GateFailureCode::Integrity),
        2 => Ok(GateFailureCode::Unavailable),
        3 => Ok(GateFailureCode::ScopeMismatch),
        4 => Ok(GateFailureCode::PolicyDenied),
        5 => Ok(GateFailureCode::Timeout),
        6 => Ok(GateFailureCode::Capacity),
        7 => Ok(GateFailureCode::Privacy),
        8 => Ok(GateFailureCode::UnresolvedEffect),
        actual => Err(MigrationCodecError::UnknownTag {
            field: "gate_failure",
            actual,
        }),
    }
}

fn gate_revocation_tag(reason: GateRevocationReason) -> u8 {
    match reason {
        GateRevocationReason::SecurityRevoked => 1,
        GateRevocationReason::ArtifactChanged => 2,
        GateRevocationReason::GenerationReplaced => 3,
        GateRevocationReason::OperatorRevoked => 4,
    }
}

fn decode_gate_revocation(tag: u8) -> Result<GateRevocationReason, MigrationCodecError> {
    match tag {
        1 => Ok(GateRevocationReason::SecurityRevoked),
        2 => Ok(GateRevocationReason::ArtifactChanged),
        3 => Ok(GateRevocationReason::GenerationReplaced),
        4 => Ok(GateRevocationReason::OperatorRevoked),
        actual => Err(MigrationCodecError::UnknownTag {
            field: "gate_revocation",
            actual,
        }),
    }
}

fn audit_action_tag(action: MigrationAuditAction) -> u8 {
    match action {
        MigrationAuditAction::StagePlan => 1,
        MigrationAuditAction::RecordEvidence => 2,
        MigrationAuditAction::AdvancePhase => 3,
        MigrationAuditAction::PrepareCutover => 4,
        MigrationAuditAction::CommitCutover => 5,
        MigrationAuditAction::StartRollbackCycle => 6,
        MigrationAuditAction::BeginDrain => 7,
        MigrationAuditAction::RetireSource => 8,
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

fn decode_cutover_intent(tag: u8) -> Result<CutoverIntent, MigrationCodecError> {
    match tag {
        1 => Ok(CutoverIntent::InternalCanary),
        2 => Ok(CutoverIntent::CohortExpansion),
        3 => Ok(CutoverIntent::DefaultNative),
        4 => Ok(CutoverIntent::Rollback),
        actual => Err(MigrationCodecError::UnknownTag {
            field: "cutover_intent",
            actual,
        }),
    }
}

fn versioned_decoder(bytes: &[u8]) -> Result<Decoder<'_>, MigrationCodecError> {
    let mut decoder = Decoder::new(bytes);
    let version = decoder.read_u8()?;
    if version != CODEC_VERSION {
        return Err(MigrationCodecError::UnknownVersion { actual: version });
    }
    Ok(decoder)
}

fn invalid(field: &'static str) -> MigrationCodecError {
    MigrationCodecError::InvalidValue { field }
}

fn write_blob(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &[u8],
) -> Result<(), MigrationCodecError> {
    let length = u32::try_from(value.len()).map_err(|_| MigrationCodecError::Oversized {
        field,
        max: u32::MAX as usize,
        actual: value.len(),
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn write_string(
    output: &mut Vec<u8>,
    field: &'static str,
    value: &str,
) -> Result<(), MigrationCodecError> {
    let length = u16::try_from(value.len()).map_err(|_| MigrationCodecError::Oversized {
        field,
        max: usize::from(u16::MAX),
        actual: value.len(),
    })?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn runtime_generation(
    value: String,
    field: &'static str,
) -> Result<RuntimeGenerationRef, MigrationCodecError> {
    RuntimeGenerationRef::new(value).map_err(|error| match error {
        MigrationValueError::TooLong { max, actual, .. } => {
            MigrationCodecError::Oversized { field, max, actual }
        }
        _ => MigrationCodecError::InvalidValue { field },
    })
}

struct Decoder<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, MigrationCodecError> {
        let value = *self
            .bytes
            .get(self.position)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position += 1;
        Ok(value)
    }

    fn read_u16(&mut self) -> Result<u16, MigrationCodecError> {
        Ok(u16::from_be_bytes(self.read_exact::<2>()?))
    }

    fn read_u32(&mut self) -> Result<u32, MigrationCodecError> {
        Ok(u32::from_be_bytes(self.read_exact::<4>()?))
    }

    fn read_u64(&mut self) -> Result<u64, MigrationCodecError> {
        Ok(u64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_i64(&mut self) -> Result<i64, MigrationCodecError> {
        Ok(i64::from_be_bytes(self.read_exact::<8>()?))
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], MigrationCodecError> {
        self.read_exact::<N>()
    }

    fn read_string(&mut self, field: &'static str) -> Result<String, MigrationCodecError> {
        let length = usize::from(self.read_u16()?);
        let end = self
            .position
            .checked_add(length)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position = end;
        String::from_utf8(value.to_vec()).map_err(|_| MigrationCodecError::InvalidUtf8 { field })
    }

    fn read_blob(&mut self, field: &'static str) -> Result<&'a [u8], MigrationCodecError> {
        let length =
            usize::try_from(self.read_u32()?).map_err(|_| MigrationCodecError::Oversized {
                field,
                max: usize::MAX,
                actual: usize::MAX,
            })?;
        let end = self
            .position
            .checked_add(length)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        self.position = end;
        Ok(value)
    }

    fn read_exact<const N: usize>(&mut self) -> Result<[u8; N], MigrationCodecError> {
        let end = self
            .position
            .checked_add(N)
            .ok_or(MigrationCodecError::Truncated)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(MigrationCodecError::Truncated)?;
        let mut output = [0; N];
        output.copy_from_slice(value);
        self.position = end;
        Ok(output)
    }

    fn finish(self) -> Result<(), MigrationCodecError> {
        if self.position == self.bytes.len() {
            Ok(())
        } else {
            Err(MigrationCodecError::TrailingBytes {
                remaining: self.bytes.len() - self.position,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use gocode_application::migration::types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        FencingToken, MigrationCycleId, MigrationPlanId, RollbackDisposition, RoutingGeneration,
        RoutingSnapshot, RoutingUnit, RuntimeAuthority, RuntimeBinding, RuntimeGenerationRef,
    };
    use gocode_application::migration::{
        manifests::{
            ArtifactRef, ArtifactValidation, CandidateValidationReport, CutoverManifest,
            CutoverManifestFields, DrainReportArtifact, ImportDisposition, MigrationCounts,
            MigrationReport, MigrationReportFields, RollbackPolicy,
        },
        ports::CutoverIntent,
    };
    use gocode_domain::{
        id::{AggregateId, TaskRunId},
        timestamp::Timestamp,
    };

    use super::*;

    const GOLDEN_ROUTING_SNAPSHOT_HEX: &str = concat!(
        "010000000000000002",
        "000e72756e74696d652d6c6567616379",
        "000e72756e74696d652d6e6174697665",
        "0001",
        "000c636c69656e745f636c617373",
        "00077072656d69756d",
        "02",
        "000e72756e74696d652d6e6174697665",
        "0202020202020202020202020202020202020202020202020202020202020202",
        "0101010101010101010101010101010101010101010101010101010101010101",
        "0404040404040404040404040404040404040404040404040404040404040404",
        "0707070707070707070707070707070707070707070707070707070707070707",
        "01",
        "000000000000000a"
    );
    const GOLDEN_CUTOVER_MANIFEST_HEX: &str = "02001261727469666163743a2f2f6375746f7665720c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0006706c616e2d3100076379636c652d3101000a70726f64756374696f6e0001000c636c69656e745f636c61737300077072656d69756d000764656661756c7400010101010101010101010101010101010101010101010101010101010101010101020202020202020202020202020202020202020202020202020202020202020203030303030303030303030303030303030303030303030303030303030303030404040404040404040404040404040404040404040404040404040404040404001961727469666163743a2f2f736f757263652d72656c656173650d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d000e72756e74696d652d6c6567616379001c61727469666163743a2f2f63616e6469646174652d72656c656173650e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e000e72756e74696d652d6e6174697665001761727469666163743a2f2f65766964656e63652d7365740f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f001861727469666163743a2f2f696d706f72742d7265706f72740808080808080808080808080808080808080808080808080808080808080808001761727469666163743a2f2f647261696e2d7265706f72741010101010101010101010101010101010101010101010101010101010101010001f61727469666163743a2f2f63616e6469646174652d76616c69646174696f6e1111111111111111111111111111111111111111111111111111111111111111000000000000002a000000000000000201000000000000012c002161727469666163743a2f2f6f70657261746f722d617574686f72697a6174696f6e121212121212121212121212121212121212121212121212121212121212121200186375746f7665722d707265706172653a76323a61613a62620000000000000011000000000000001200000000000000c8";

    #[test]
    fn routing_snapshot_codec_has_literal_golden_bytes() {
        let bytes = encode_routing_snapshot(&golden_snapshot()).unwrap();

        assert_eq!(hex(&bytes), GOLDEN_ROUTING_SNAPSHOT_HEX);
        assert_eq!(decode_routing_snapshot(&bytes).unwrap(), golden_snapshot());
    }

    #[test]
    fn migration_codec_rejects_unknown_version_and_trailing_bytes() {
        assert_eq!(
            decode_routing_snapshot(&[0xff]),
            Err(MigrationCodecError::UnknownVersion { actual: 255 })
        );

        let mut bytes = encode_routing_snapshot(&golden_snapshot()).unwrap();
        bytes.push(0);
        assert_eq!(
            decode_routing_snapshot(&bytes),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn cutover_manifest_roundtrips_and_rejects_digest_corruption() {
        let manifest = golden_cutover_manifest();
        let bytes = encode_cutover_manifest(&manifest).unwrap();
        assert_eq!(hex(&bytes), GOLDEN_CUTOVER_MANIFEST_HEX);
        assert_eq!(decode_cutover_manifest(&bytes).unwrap(), manifest);

        let mut corrupt = bytes;
        corrupt[21..53].fill(0);
        assert_eq!(
            decode_cutover_manifest(&corrupt),
            Err(MigrationCodecError::InvalidValue { field: "manifest" })
        );
    }

    #[test]
    fn runtime_binding_codec_has_literal_bytes_and_rejects_trailing_data() {
        let generation = RuntimeGenerationRef::new("runtime-native").unwrap();
        let binding = RuntimeBinding::new(
            AggregateId::TaskRun(taskrun_id()),
            RuntimeAuthority::Candidate(generation.clone()),
            generation,
            RoutingGeneration::new(2).unwrap(),
            FencingToken::new([7; 32]).unwrap(),
            Timestamp::from_unix_micros(10),
        )
        .unwrap();
        let bytes = encode_runtime_binding(&binding).unwrap();

        assert_eq!(
            hex(&bytes),
            concat!(
                "0101",
                "018f2e3a8d5c7b208d9a000000000001",
                "02",
                "000e72756e74696d652d6e6174697665",
                "000e72756e74696d652d6e6174697665",
                "0000000000000002",
                "0707070707070707070707070707070707070707070707070707070707070707",
                "000000000000000a"
            )
        );
        assert_eq!(decode_runtime_binding(&bytes).unwrap(), binding);

        let mut trailing = bytes;
        trailing.push(0);
        assert_eq!(
            decode_runtime_binding(&trailing),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }

    #[test]
    fn report_rollback_and_retirement_codecs_are_closed_and_roundtrip() {
        let report = golden_migration_report();
        let report_bytes = encode_migration_report(&report).unwrap();
        assert_eq!(decode_migration_report(&report_bytes).unwrap(), report);

        let rollback = RollbackManifest {
            manifest: artifact("rollback", 20),
            plan_id: MigrationPlanId::new("rollback-plan").unwrap(),
            cycle_id: MigrationCycleId::new("rollback-cycle").unwrap(),
            parent_plan_id: MigrationPlanId::new("plan-1").unwrap(),
            routing_unit: golden_routing_unit(),
            candidate_high_water: 43,
            changed_state_inventory: artifact("changed-state", 21),
            reconciliation_report: artifact("reconciliation", 22),
            reverse_migration_contract: Some(artifact("reverse-contract", 23)),
            expected_routing_generation: RoutingGeneration::new(3).unwrap(),
            operator_authorization: artifact("rollback-authorization", 24),
            created_at: Timestamp::from_unix_micros(400),
        };
        let rollback_bytes = encode_rollback_manifest(&rollback).unwrap();
        assert_eq!(decode_rollback_manifest(&rollback_bytes).unwrap(), rollback);

        let retirement = RetirementManifest {
            manifest: artifact("retirement", 25),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            final_drain_report: artifact("final-drain", 26),
            final_audit: artifact("final-audit", 27),
            removal_diff: artifact("removal-diff", 28),
            retention_until: Timestamp::from_unix_micros(900),
            operator_authorization: artifact("retirement-authorization", 29),
            created_at: Timestamp::from_unix_micros(500),
        };
        let mut retirement_bytes = encode_retirement_manifest(&retirement).unwrap();
        assert_eq!(
            decode_retirement_manifest(&retirement_bytes).unwrap(),
            retirement
        );
        retirement_bytes.push(0);
        assert_eq!(
            decode_retirement_manifest(&retirement_bytes),
            Err(MigrationCodecError::TrailingBytes { remaining: 1 })
        );
    }

    fn golden_snapshot() -> RoutingSnapshot {
        let source = RuntimeGenerationRef::new("runtime-legacy").unwrap();
        let candidate = RuntimeGenerationRef::new("runtime-native").unwrap();
        RoutingSnapshot {
            routing_generation: RoutingGeneration::new(2).unwrap(),
            source,
            candidate: candidate.clone(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            authority: RuntimeAuthority::Candidate(candidate),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            profile_digest: ArtifactDigest::from_bytes([1; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
            fencing_token: FencingToken::new([7; 32]).unwrap(),
            rollback_disposition: RollbackDisposition::Eligible,
            committed_at: Timestamp::from_unix_micros(10),
        }
    }

    fn golden_cutover_manifest() -> CutoverManifest {
        let report = golden_migration_report();
        CutoverManifest::new(CutoverManifestFields {
            manifest: artifact("cutover", 12),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            intent: CutoverIntent::InternalCanary,
            routing_unit: golden_routing_unit(),
            source_release: artifact("source-release", 13),
            source_generation: RuntimeGenerationRef::new("runtime-legacy").unwrap(),
            candidate_release: artifact("candidate-release", 14),
            candidate_generation: RuntimeGenerationRef::new("runtime-native").unwrap(),
            frozen_evidence_set: artifact("evidence-set", 15),
            migration_report: report,
            drain_report: DrainReportArtifact {
                report: artifact("drain-report", 16),
                complete: true,
                timed_out: false,
                unresolved_effects: 0,
                source_high_water: 42,
            },
            candidate_validation: CandidateValidationReport {
                report: artifact("candidate-validation", 17),
                validation: ArtifactValidation::Passed,
            },
            expected_routing_generation: RoutingGeneration::new(2).unwrap(),
            routing_generation_at_prepare: RoutingGeneration::new(2).unwrap(),
            rollback_policy: RollbackPolicy::BeforeCandidateWrites,
            retention_until: Timestamp::from_unix_micros(300),
            operator_authorization: artifact("operator-authorization", 18),
            prepared_transition_id: "cutover-prepare:v2:aa:bb".to_owned(),
            expected_plan_version: 17,
            prepared_plan_version: 18,
            prepared_at: Timestamp::from_unix_micros(200),
        })
        .unwrap()
    }

    fn golden_migration_report() -> MigrationReport {
        MigrationReport::new(MigrationReportFields {
            report: artifact("import-report", 8),
            plan_id: MigrationPlanId::new("plan-1").unwrap(),
            cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
            source_snapshot: artifact("source-snapshot", 9),
            source_high_water: 42,
            source_generation: RuntimeGenerationRef::new("runtime-legacy").unwrap(),
            candidate_generation: RuntimeGenerationRef::new("runtime-native").unwrap(),
            counts: MigrationCounts {
                imported: 10,
                skipped: 0,
                unsupported: 0,
                rejected: 0,
                unknown: 0,
                lossy: 0,
                ambiguous: 0,
            },
            schema: artifact("schema", 3),
            mapping: artifact("mapping", 11),
            profile: artifact("profile", 1),
            integrity: ArtifactValidation::Passed,
            rebuild: ArtifactValidation::Passed,
            disposition: ImportDisposition::Clean,
            created_at: Timestamp::from_unix_micros(100),
        })
        .unwrap()
    }

    fn golden_routing_unit() -> RoutingUnit {
        RoutingUnit {
            deployment: DeploymentId::new("production").unwrap(),
            cohort: CohortSelector::new(vec![
                CohortDimension::new("client_class", "premium").unwrap(),
            ])
            .unwrap(),
            feature_profile: FeatureProfileRef::new(
                "default",
                1,
                ArtifactDigest::from_bytes([1; 32]),
            )
            .unwrap(),
            contract_digest: ArtifactDigest::from_bytes([2; 32]),
            schema_digest: ArtifactDigest::from_bytes([3; 32]),
            config_digest: ArtifactDigest::from_bytes([4; 32]),
        }
    }

    fn artifact(name: &str, byte: u8) -> ArtifactRef {
        ArtifactRef::new(
            format!("artifact://{name}"),
            ArtifactDigest::from_bytes([byte; 32]),
        )
        .unwrap()
    }

    fn taskrun_id() -> TaskRunId {
        "018f2e3a-8d5c-7b20-8d9a-000000000001".parse().unwrap()
    }

    fn hex(bytes: &[u8]) -> String {
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use core::fmt::Write as _;
            write!(&mut output, "{byte:02x}").unwrap();
        }
        output
    }
}
