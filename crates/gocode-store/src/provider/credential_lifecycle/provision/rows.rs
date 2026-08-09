type RawProvision = (Vec<u8>, Vec<u8>, i64, Vec<u8>, String);
type RawProvisionByOperation = (Vec<u8>, String, i64, Vec<u8>, String);

fn load_pending_provision(
    connection: &rusqlite::Connection,
    provider: &gocode_provider::ProviderId,
) -> Result<Option<CredentialProvision>, CredentialLifecycleError> {
    let raw: Option<RawProvision> = connection
        .query_row(
            "SELECT operation_id, source_revision_id, credential_version,
                    ref_digest, provision_state
             FROM provider_credential_provisions
             WHERE provider_id=?1 AND provision_state!='ACTIVATED'",
            [provider.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(map_sql)?;
    let Some(raw) = raw else {
        return Ok(None);
    };
    let provision = decode_provision(provider.clone(), raw)?;
    let row = load_row(connection, &provision.reference)?
        .ok_or(CredentialLifecycleError::CorruptState)?;
    validate_row_ref(&row, &provision.reference)?;
    let valid = matches!(
        (provision.stage, row.state),
        (ProvisionStage::Prepared, CredentialVersionState::Prepared)
            | (ProvisionStage::NativeCreated, CredentialVersionState::Prepared)
            | (ProvisionStage::NativeCreated, CredentialVersionState::Active)
    );
    if !valid {
        return Err(CredentialLifecycleError::LifecycleClosed);
    }
    Ok(Some(provision))
}

fn load_provision_by_operation(
    connection: &rusqlite::Connection,
    operation_id: [u8; 16],
) -> Result<Option<CredentialProvision>, CredentialLifecycleError> {
    let raw: Option<RawProvisionByOperation> = connection
        .query_row(
            "SELECT source_revision_id, provider_id, credential_version,
                    ref_digest, provision_state
             FROM provider_credential_provisions WHERE operation_id=?1",
            [operation_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(|(source, provider, version, digest, stage)| {
        let provider = gocode_provider::ProviderId::new(provider)
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        decode_provision(
            provider,
            (operation_id.to_vec(), source, version, digest, stage),
        )
    })
    .transpose()
}

fn decode_provision(
    provider: gocode_provider::ProviderId,
    raw: RawProvision,
) -> Result<CredentialProvision, CredentialLifecycleError> {
    let (operation, source, version, digest, state) = raw;
    let operation_id = operation
        .try_into()
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    let source_revision_id = source
        .try_into()
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
    if source_revision_id == [0; 16] {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let version = u64::try_from(version).map_err(|_| CredentialLifecycleError::CorruptState)?;
    let reference = CredentialVersionRef::new(provider, version)?;
    if digest.as_slice() != reference.ref_digest() {
        return Err(CredentialLifecycleError::CorruptState);
    }
    let stage = match state.as_str() {
        "PREPARED" => ProvisionStage::Prepared,
        "NATIVE_CREATED" => ProvisionStage::NativeCreated,
        "ACTIVATED" => ProvisionStage::Activated,
        _ => return Err(CredentialLifecycleError::CorruptState),
    };
    Ok(CredentialProvision {
        operation_id,
        source_revision_id,
        reference,
        stage,
    })
}
