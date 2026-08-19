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
        MigrationAuditAction::EmergencyRevoke => 9,
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
