fn advance_provision(
    store: &SqliteProviderCredentialLifecycleStore,
    provision: &CredentialProvision,
    target: &str,
    require_active: bool,
) -> Result<CredentialProvision, CredentialLifecycleError> {
    let mut connection = store.connection.lock().map_err(map_lock)?;
    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(map_sql)?;
    let existing = load_provision_by_operation(&transaction, provision.operation_id)?
        .ok_or(CredentialLifecycleError::NotFound)?;
    if existing.operation_id != provision.operation_id
        || existing.source_revision_id != provision.source_revision_id
        || existing.reference != provision.reference
    {
        return Err(CredentialLifecycleError::Conflict);
    }
    if require_active {
        let row = load_row(&transaction, &provision.reference)?
            .ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, &provision.reference)?;
        if row.state != CredentialVersionState::Active {
            return Err(CredentialLifecycleError::Conflict);
        }
    }
    let target_stage = if target == "NATIVE_CREATED" {
        ProvisionStage::NativeCreated
    } else {
        ProvisionStage::Activated
    };
    if existing.stage != target_stage && existing.stage != ProvisionStage::Activated {
        let expected = if target_stage == ProvisionStage::NativeCreated {
            ProvisionStage::Prepared
        } else {
            ProvisionStage::NativeCreated
        };
        if existing.stage != expected {
            return Err(CredentialLifecycleError::Conflict);
        }
        transaction
            .execute(
                "UPDATE provider_credential_provisions SET provision_state=?1
                 WHERE operation_id=?2",
                params![target, provision.operation_id.as_slice()],
            )
            .map_err(map_sql)?;
    }
    if target_stage == ProvisionStage::NativeCreated {
        store.authority.invalidate_native_create_claims()?;
    }
    transaction.commit().map_err(map_sql)?;
    Ok(CredentialProvision {
        operation_id: provision.operation_id,
        source_revision_id: provision.source_revision_id,
        reference: provision.reference.clone(),
        stage: if existing.stage == ProvisionStage::Activated {
            ProvisionStage::Activated
        } else {
            target_stage
        },
    })
}
