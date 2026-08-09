/// Durable non-secret identity and stage for one credential provisioning command.
#[derive(Clone, PartialEq, Eq)]
pub struct CredentialProvision {
    operation_id: [u8; 16],
    source_revision_id: [u8; 16],
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

impl core::fmt::Debug for CredentialProvision {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialProvision")
            .field("identity", &"<opaque>")
            .field("reference", &self.reference)
            .field("stage", &self.stage)
            .finish()
    }
}

impl SqliteProviderCredentialLifecycleStore {
    /// Issues a non-forgeable non-secret source revision for one command.
    pub fn provision_source(
        &self,
        revision_id: [u8; 16],
    ) -> Result<CredentialProvisionSource, CredentialLifecycleError> {
        self.authority.issue_provision_source(revision_id)
    }

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
        source: &CredentialProvisionSource,
    ) -> Result<CredentialProvision, CredentialLifecycleError> {
        if operation_id == [0; 16] {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let source_revision_id = *self.authority.authorize_provision_source(source)?;
        let mut connection = self.connection.lock().map_err(map_lock)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(map_sql)?;
        if let Some(existing) = load_provision_by_operation(&transaction, operation_id)? {
            return if existing.reference.provider() == provider
                && existing.source_revision_id == source_revision_id
            {
                transaction.commit().map_err(map_sql)?;
                Ok(existing)
            } else {
                Err(CredentialLifecycleError::Conflict)
            };
        }
        if let Some(existing) = load_pending_provision(&transaction, provider)? {
            return if existing.operation_id == operation_id
                && existing.source_revision_id == source_revision_id
            {
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
                 (operation_id, source_revision_id, provider_id, credential_version,
                  ref_digest, provision_state)
                 VALUES (?1, ?2, ?3, ?4, ?5, 'PREPARED')",
                params![
                    operation_id.as_slice(),
                    source_revision_id.as_slice(),
                    provider.as_str(),
                    to_i64(reference.version())?,
                    reference.ref_digest().as_slice()
                ],
            )
            .map_err(map_sql)?;
        transaction.commit().map_err(map_sql)?;
        Ok(CredentialProvision {
            operation_id,
            source_revision_id,
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

    /// Claims native create work only while the exact version is PREPARED.
    pub fn claim_native_create(
        &self,
        provision: &CredentialProvision,
    ) -> Result<CredentialNativeCreateClaim, CredentialLifecycleError> {
        let mut connection = self.connection.lock().map_err(map_lock)?;
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
        let row = load_row(&transaction, &provision.reference)?
            .ok_or(CredentialLifecycleError::NotFound)?;
        validate_row_ref(&row, &provision.reference)?;
        if row.state != CredentialVersionState::Prepared || row.tombstone_digest.is_some() {
            return Err(CredentialLifecycleError::LifecycleClosed);
        }
        if existing.stage == ProvisionStage::Activated {
            return Err(CredentialLifecycleError::Conflict);
        }
        transaction.commit().map_err(map_sql)?;
        let source = self
            .authority
            .issue_provision_source(provision.source_revision_id)?;
        self.authority
            .issue_native_create(provision.reference.clone(), &source)
    }

    /// Completes a provision only after the exact version is ACTIVE.
    pub fn complete_provision(
        &self,
        provision: &CredentialProvision,
    ) -> Result<(), CredentialLifecycleError> {
        advance_provision(self, provision, "ACTIVATED", true).map(|_| ())
    }
}

include!("provision/rows.rs");
include!("provision/allocation.rs");
include!("provision/advance.rs");
