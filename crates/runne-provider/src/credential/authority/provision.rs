/// Authority-issued immutable non-secret identity of credential source input.
pub struct CredentialProvisionSource {
    revision_id: [u8; 16],
    seal: Arc<AuthoritySeal>,
}

/// Non-cloneable native create work issued only for durable PREPARED state.
pub struct CredentialNativeCreateClaim {
    reference: CredentialVersionRef,
    source_revision_id: [u8; 16],
    generation: u64,
    seal: Arc<AuthoritySeal>,
    validator: Arc<dyn CredentialNativeCreateValidator>,
}

/// Store-owned point-of-use validation for one durable native-create claim.
pub trait CredentialNativeCreateValidator: Send + Sync {
    /// Revalidates the exact non-tombstoned `PREPARED` lifecycle stage.
    fn validate(&self) -> Result<(), CredentialLifecycleError>;
}

/// Native-create authorization that blocks lifecycle progression until dropped.
pub struct CredentialNativeCreateAuthorization<'a> {
    reference: &'a CredentialVersionRef,
    _generation: std::sync::RwLockReadGuard<'a, u64>,
}

/// Guarded issuer that prevents lifecycle progression during claim admission.
pub struct CredentialNativeCreateIssuer<'a> {
    authority: &'a CredentialLifecycleAuthority,
    generation: std::sync::RwLockReadGuard<'a, u64>,
}

/// Exclusive guard held until an advancing lifecycle commit completes.
pub struct CredentialNativeCreateProgression<'a> {
    _generation: std::sync::RwLockWriteGuard<'a, u64>,
}

impl CredentialNativeCreateAuthorization<'_> {
    /// Exact version authorized for native immutable creation.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        self.reference
    }
}

impl CredentialNativeCreateClaim {
    /// Exact version whose native bytes may be created idempotently.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }

    /// Returns the authority-issued non-secret source revision for this create.
    pub const fn source_revision_id(&self) -> &[u8; 16] {
        &self.source_revision_id
    }
}

impl core::fmt::Debug for CredentialNativeCreateClaim {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("CredentialNativeCreateClaim")
            .field("reference", &self.reference)
            .field("source", &"<opaque>")
            .field("authority", &"<opaque>")
            .finish()
    }
}

impl core::fmt::Debug for CredentialProvisionSource {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("CredentialProvisionSource(<opaque>)")
    }
}

impl CredentialLifecycleAuthority {
    /// Issues one opaque non-secret source revision identity.
    pub fn issue_provision_source(
        &self,
        revision_id: [u8; 16],
    ) -> Result<CredentialProvisionSource, CredentialLifecycleError> {
        if revision_id == [0; 16] {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        Ok(CredentialProvisionSource {
            revision_id,
            seal: Arc::clone(&self.provision),
        })
    }

    /// Validates that a source revision belongs to this lifecycle authority.
    pub fn authorize_provision_source<'a>(
        &self,
        source: &'a CredentialProvisionSource,
    ) -> Result<&'a [u8; 16], CredentialLifecycleError> {
        if Arc::ptr_eq(&self.provision, &source.seal) {
            Ok(&source.revision_id)
        } else {
            Err(CredentialLifecycleError::StaleLease)
        }
    }

    /// Locks generation while durable claim admission is evaluated.
    pub fn native_create_issuer(
        &self,
    ) -> Result<CredentialNativeCreateIssuer<'_>, CredentialLifecycleError> {
        let generation = self
            .provision_generation
            .read()
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        Ok(CredentialNativeCreateIssuer {
            authority: self,
            generation,
        })
    }

    /// Revokes claims and locks generation through a lifecycle commit.
    pub fn invalidate_native_create_claims(
        &self,
    ) -> Result<CredentialNativeCreateProgression<'_>, CredentialLifecycleError> {
        let mut generation = self
            .provision_generation
            .write()
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        *generation = generation
            .checked_add(1)
            .ok_or(CredentialLifecycleError::CorruptState)?;
        Ok(CredentialNativeCreateProgression {
            _generation: generation,
        })
    }

    /// Reports whether lifecycle progression currently owns generation.
    #[doc(hidden)]
    pub fn native_create_progression_is_exclusive(
        &self,
    ) -> Result<bool, CredentialLifecycleError> {
        match self.provision_generation.try_read() {
            Ok(generation) => {
                drop(generation);
                Ok(false)
            }
            Err(std::sync::TryLockError::WouldBlock) => Ok(true),
            Err(std::sync::TryLockError::Poisoned(_)) => {
                Err(CredentialLifecycleError::CorruptState)
            }
        }
    }
}

impl CredentialNativeCreateIssuer<'_> {
    /// Issues native create work bound to durable point-of-use validation.
    pub fn issue_native_create(
        &self,
        reference: CredentialVersionRef,
        source: &CredentialProvisionSource,
        validator: Arc<dyn CredentialNativeCreateValidator>,
    ) -> Result<CredentialNativeCreateClaim, CredentialLifecycleError> {
        let source_revision_id = *self.authority.authorize_provision_source(source)?;
        Ok(CredentialNativeCreateClaim {
            reference,
            source_revision_id,
            generation: *self.generation,
            seal: Arc::clone(&self.authority.provision),
            validator,
        })
    }
}

impl NativeCredentialAuthority {
    /// Revalidates and guards non-cloneable `PREPARED` native create work.
    pub fn authorize_create<'a>(
        &'a self,
        claim: &'a CredentialNativeCreateClaim,
    ) -> Result<CredentialNativeCreateAuthorization<'a>, CredentialLifecycleError> {
        let generation = self
            .provision_generation
            .read()
            .map_err(|_| CredentialLifecycleError::CorruptState)?;
        if !Arc::ptr_eq(&self.provision, &claim.seal)
            || claim.source_revision_id == [0; 16]
            || *generation != claim.generation
        {
            return Err(CredentialLifecycleError::StaleLease);
        }
        claim.validator.validate()?;
        Ok(CredentialNativeCreateAuthorization {
            reference: &claim.reference,
            _generation: generation,
        })
    }
}
