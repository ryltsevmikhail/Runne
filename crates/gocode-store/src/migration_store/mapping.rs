fn decode_command_id(bytes: &[u8]) -> Result<CommandId, MigrationStoreError> {
    let bytes: [u8; 16] = bytes
        .try_into()
        .map_err(|_| MigrationStoreError::CorruptData)?;
    CommandId::from_bytes(bytes)
        .to_string()
        .parse()
        .map_err(|_| MigrationStoreError::CorruptData)
}

fn decode_dispatch_status(value: i64) -> Result<DispatchIntentStatus, MigrationStoreError> {
    match value {
        1 => Ok(DispatchIntentStatus::Pending),
        2 => Ok(DispatchIntentStatus::Indeterminate),
        3 => Ok(DispatchIntentStatus::Accepted),
        4 => Ok(DispatchIntentStatus::RejectedBeforeAcceptance),
        _ => Err(MigrationStoreError::CorruptData),
    }
}

const fn dispatch_status_tag(status: DispatchIntentStatus) -> i64 {
    match status {
        DispatchIntentStatus::Pending => 1,
        DispatchIntentStatus::Indeterminate => 2,
        DispatchIntentStatus::Accepted => 3,
        DispatchIntentStatus::RejectedBeforeAcceptance => 4,
    }
}

fn snapshot_matches_unit(snapshot: &RoutingSnapshot, unit: &RoutingUnit) -> bool {
    snapshot.cohort == unit.cohort
        && snapshot.contract_digest == unit.contract_digest
        && snapshot.profile_digest == unit.feature_profile.profile_digest
        && snapshot.config_digest == unit.config_digest
}

fn map_runtime_binding_write_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else if is_constraint(&error) {
        MigrationStoreError::RuntimeBindingConflict
    } else {
        MigrationStoreError::IntegrityViolation
    }
}

fn map_dispatch_intent_write_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else if is_constraint(&error) {
        MigrationStoreError::DispatchIntentConflict
    } else {
        MigrationStoreError::IntegrityViolation
    }
}

fn aggregate_parts(aggregate_id: &AggregateId) -> Result<(i64, [u8; 16]), MigrationStoreError> {
    match aggregate_id {
        AggregateId::TaskRun(id) => Ok((1, *id.as_bytes())),
        AggregateId::Conversation(id) => Ok((2, *id.as_bytes())),
        AggregateId::Workspace(_) => Err(MigrationStoreError::IntegrityViolation),
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

fn status_tag(status: MigrationPlanStatus) -> u8 {
    match status {
        MigrationPlanStatus::Active => 1,
        MigrationPlanStatus::Retired => 2,
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

fn u64_to_i64(value: u64) -> Result<i64, MigrationStoreError> {
    i64::try_from(value).map_err(|_| MigrationStoreError::ArithmeticOverflow)
}

fn map_codec_error(error: MigrationCodecError) -> MigrationStoreError {
    match error {
        MigrationCodecError::UnknownVersion { .. } => MigrationStoreError::UnsupportedSchema,
        MigrationCodecError::Truncated
        | MigrationCodecError::TrailingBytes { .. }
        | MigrationCodecError::UnknownTag { .. }
        | MigrationCodecError::Oversized { .. }
        | MigrationCodecError::InvalidUtf8 { .. }
        | MigrationCodecError::InvalidValue { .. } => MigrationStoreError::CorruptData,
    }
}

fn map_open_error(_error: SqliteError) -> MigrationStoreError {
    MigrationStoreError::Unavailable
}

fn map_read_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else {
        MigrationStoreError::CorruptData
    }
}

fn map_write_error(error: SqliteError) -> MigrationStoreError {
    if is_busy(&error) {
        MigrationStoreError::Unavailable
    } else {
        MigrationStoreError::IntegrityViolation
    }
}

fn is_busy(error: &SqliteError) -> bool {
    matches!(
        error,
        SqliteError::SqliteFailure(
            rusqlite::ffi::Error {
                code: ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked,
                ..
            },
            _
        )
    )
}

fn is_constraint(error: &SqliteError) -> bool {
    matches!(
        error,
        SqliteError::SqliteFailure(
            rusqlite::ffi::Error {
                code: ErrorCode::ConstraintViolation,
                ..
            },
            _
        )
    )
}
