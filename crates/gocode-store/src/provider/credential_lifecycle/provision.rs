/// Durable non-secret identity and stage for one credential provisioning command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialProvision {
    operation_id: [u8; 16],
    reference: CredentialVersionRef,
    stage: ProvisionStage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvisionStage {
    Prepared,
    NativeCreated,
    Activated,
}

impl CredentialProvision {
    /// Stable command identity used for exact crash replay.
    pub const fn operation_id(&self) -> &[u8; 16] {
        &self.operation_id
    }

    /// Exact credential version reserved by the command.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }

    /// Whether native create completed and was durably acknowledged.
    pub const fn native_created(&self) -> bool {
        !matches!(self.stage, ProvisionStage::Prepared)
    }
}

impl SqliteProviderCredentialLifecycleStore {
    /// Reads the sole incomplete provider provisioning command.
    pub fn pending_provision(
        &self,
        provider: &gocode_provider::ProviderId,
    ) -> Result<Option<CredentialProvision>, CredentialLifecycleError> {
        let connection = self.connection.lock().map_err(map_lock)?;
        load_pending_provision(&connection, provider)
    }

    /// Begins a command or exactly replays its durable operation identity.
    pub fn begin_provision(
        &self,
        provider: &gocode_provider::ProviderId,
        operation_id: [u8; 16],
    ) -> Result<CredentialProvision, CredentialLifecycleError> {
        if operation_id == [0; 16] {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let mut connection = self.connection.lock().map_err(map_lock)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(existing) = load_provision_by_operation(&transaction, operation_id)? {
            return if existing.reference.provider() == provider {
                transaction.commit().map_err(map_sql)?;
                Ok(existing)
            } else {
                Err(CredentialLifecycleError::Conflict)
            };
        }
        if let Some(existing) = load_pending_provision(&transaction, provider)? {
            return if existing.operation_id == operation_id {
                transaction.commit().map_err(map_sql)?;
                Ok(existing)
            } else {
                Err(CredentialLifecycleError::Conflict)
            };
        }
        let reference = adopt_or_create_prepared(&transaction, provider)?;
        transaction
            .execute(
                "INSERT INTO provider_credential_provisions
                 (operation_id, provider_id, credential_version, ref_digest, provision_state)
                 VALUES (?1, ?2, ?3, ?4, 'PREPARED')",
                params![
                    operation_id.as_slice(),
                    provider.as_str(),
                    to_i64(reference.version())?,
                    reference.ref_digest().as_slice()
                ],
            )
            .map_err(map_sql)?;
        transaction.commit().map_err(map_sql)?;
        Ok(CredentialProvision {
            operation_id,
            reference,
            stage: ProvisionStage::Prepared,
        })
    }

    /// Records successful native create/status validation for exact replay.
    pub fn mark_native_created(
        &self,
        provision: &CredentialProvision,
    ) -> Result<CredentialProvision, CredentialLifecycleError> {
        advance_provision(self, provision, "NATIVE_CREATED", false)
    }

    /// Completes a provision only after the exact version is ACTIVE.
    pub fn complete_provision(
        &self,
        provision: &CredentialProvision,
    ) -> Result<(), CredentialLifecycleError> {
        advance_provision(self, provision, "ACTIVATED", true).map(|_| ())
    }
}

fn load_pending_provision(
    connection: &rusqlite::Connection,
    provider: &gocode_provider::ProviderId,
) -> Result<Option<CredentialProvision>, CredentialLifecycleError> {
    let raw: Option<(Vec<u8>, i64, Vec<u8>, String)> = connection
        .query_row(
            "SELECT operation_id, credential_version, ref_digest, provision_state
             FROM provider_credential_provisions
             WHERE provider_id=?1 AND provision_state!='ACTIVATED'",
            [provider.as_str()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(|raw| decode_provision(provider.clone(), raw))
    .transpose()
}

fn load_provision_by_operation(
    connection: &rusqlite::Connection,
    operation_id: [u8; 16],
) -> Result<Option<CredentialProvision>, CredentialLifecycleError> {
    let raw: Option<(String, i64, Vec<u8>, String)> = connection
        .query_row(
            "SELECT provider_id, credential_version, ref_digest, provision_state
             FROM provider_credential_provisions WHERE operation_id=?1",
            [operation_id.as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()
        .map_err(map_sql)?;
    raw.map(|(provider, version, digest, stage)| {
        let provider = gocode_provider::ProviderId::new(provider)
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        decode_provision(provider, (operation_id.to_vec(), version, digest, stage))
    })
    .transpose()
}

fn decode_provision(
    provider: gocode_provider::ProviderId,
    raw: (Vec<u8>, i64, Vec<u8>, String),
) -> Result<CredentialProvision, CredentialLifecycleError> {
    let (operation, version, digest, state) = raw;
    let operation_id = operation
        .try_into()
        .map_err(|_| CredentialLifecycleError::CorruptState)?;
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
        reference,
        stage,
    })
}

fn adopt_or_create_prepared(
    transaction: &rusqlite::Transaction<'_>,
    provider: &gocode_provider::ProviderId,
) -> Result<CredentialVersionRef, CredentialLifecycleError> {
    let mut statement = transaction
        .prepare(
            "SELECT credential_version, ref_digest FROM provider_credential_versions
             WHERE provider_id=?1 AND lifecycle_state='PREPARED'
             ORDER BY credential_version",
        )
        .map_err(map_sql)?;
    let prepared = statement
        .query_map([provider.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?))
        })
        .map_err(map_sql)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(map_sql)?;
    if prepared.len() > 1 {
        return Err(CredentialLifecycleError::Conflict);
    }
    if let Some((version, digest)) = prepared.into_iter().next() {
        let version =
            u64::try_from(version).map_err(|_| CredentialLifecycleError::CorruptState)?;
        let reference = CredentialVersionRef::new(provider.clone(), version)?;
        if digest.as_slice() != reference.ref_digest() {
            return Err(CredentialLifecycleError::CorruptState);
        }
        return Ok(reference);
    }
    let high_water: i64 = transaction
        .query_row(
            "SELECT COALESCE(MAX(credential_version), 0)
             FROM provider_credential_versions WHERE provider_id=?1",
            [provider.as_str()],
            |row| row.get(0),
        )
        .map_err(map_sql)?;
    let version = u64::try_from(high_water)
        .map_err(|_| CredentialLifecycleError::CorruptState)?
        .checked_add(1)
        .ok_or(CredentialLifecycleError::InvalidInput)?;
    let reference = CredentialVersionRef::new(provider.clone(), version)?;
    transaction
        .execute(
            "INSERT INTO provider_credential_versions
             (provider_id, credential_version, ref_digest, lifecycle_state)
             VALUES (?1, ?2, ?3, 'PREPARED')",
            params![
                provider.as_str(),
                to_i64(version)?,
                reference.ref_digest().as_slice()
            ],
        )
        .map_err(map_sql)?;
    Ok(reference)
}

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
    if existing.operation_id != provision.operation_id || existing.reference != provision.reference {
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
    transaction.commit().map_err(map_sql)?;
    Ok(CredentialProvision {
        operation_id: provision.operation_id,
        reference: provision.reference.clone(),
        stage: if existing.stage == ProvisionStage::Activated {
            ProvisionStage::Activated
        } else {
            target_stage
        },
    })
}
