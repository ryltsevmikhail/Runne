use runne_provider::{
    CredentialDispatchCapability, CredentialFence, CredentialLease, CredentialLifecycleRevision,
    CredentialVersionRef, DispatchAttemptId, ProviderCallDigestVersion, ProviderDispatchClaim,
    ProviderId, ProviderStreamId,
};

use super::PreparedProviderRecord;
use super::ProviderRuntimeLaunchCapability;
use super::SqliteProviderCredentialLifecycleStore;

mod online;
pub(crate) use online::{OnlineCredentialDispatchBinding, OnlineEffectStartBinding};

#[derive(Debug, Clone)]
pub(super) struct OnlineDispatchSeal {
    provider: ProviderId,
    active: CredentialVersionRef,
    lifecycle_revision: u64,
    credential_fence: u64,
    launch_generation: u64,
}

impl OnlineDispatchSeal {
    pub(super) fn new(
        provider: ProviderId,
        active: CredentialVersionRef,
        lifecycle_revision: u64,
        credential_fence: u64,
        launch_generation: u64,
    ) -> Self {
        Self {
            provider,
            active,
            lifecycle_revision,
            credential_fence,
            launch_generation,
        }
    }
}

/// Exact credential authority required by one coordinator instance.
#[derive(Clone, Copy)]
pub struct CredentialDispatchAuthority<'a> {
    pub(super) store: &'a SqliteProviderCredentialLifecycleStore,
    pub(super) launch: &'a ProviderRuntimeLaunchCapability,
}

impl<'a> CredentialDispatchAuthority<'a> {
    /// Binds the lifecycle store to one exact activated runtime launch.
    pub const fn new(
        store: &'a SqliteProviderCredentialLifecycleStore,
        launch: &'a ProviderRuntimeLaunchCapability,
    ) -> Self {
        Self { store, launch }
    }
}

/// Non-forgeable store-produced active credential lease/fence tuple.
#[derive(Debug, Clone)]
pub struct CredentialDispatchBinding(CredentialDispatchCapability, Option<OnlineDispatchSeal>);

impl PartialEq for CredentialDispatchBinding {
    fn eq(&self, other: &Self) -> bool {
        self.lease() == other.lease()
    }
}

impl Eq for CredentialDispatchBinding {}

impl CredentialDispatchBinding {
    pub(super) const fn from_authoritative_capability(
        capability: CredentialDispatchCapability,
    ) -> Self {
        Self(capability, None)
    }

    pub(super) fn with_online_seal(mut self, seal: OnlineDispatchSeal) -> Self {
        self.1 = Some(seal);
        self
    }

    /// Returns the active version reference.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        self.0.version_ref()
    }

    /// Returns the active owner identity.
    pub const fn owner(&self) -> &[u8; 16] {
        self.0.lease().owner()
    }

    /// Returns the active lease expiry.
    pub const fn expires_at(&self) -> i64 {
        self.0.lease().expires_at()
    }

    /// Returns the active fencing token.
    pub const fn fencing_token(&self) -> u64 {
        self.0.lease().fencing_token()
    }

    pub(super) const fn lease(&self) -> &CredentialLease {
        self.0.lease()
    }

    /// Returns the native-load capability bound to this authoritative lease.
    pub const fn native_capability(&self) -> &CredentialDispatchCapability {
        &self.0
    }

    /// Returns the lifecycle/fence tuple captured by the online authorization
    /// CAS and required for point-of-use credential reads.
    ///
    /// # Errors
    ///
    /// Rejects fixture-only or corrupt bindings without an online seal.
    pub fn point_of_use_revisions(
        &self,
    ) -> Result<
        (CredentialLifecycleRevision, CredentialFence),
        runne_provider::CredentialLifecycleError,
    > {
        let seal = self
            .1
            .as_ref()
            .ok_or(runne_provider::CredentialLifecycleError::StaleLease)?;
        Ok((
            CredentialLifecycleRevision::new(seal.lifecycle_revision)
                .map_err(|_| runne_provider::CredentialLifecycleError::CorruptState)?,
            CredentialFence::new(seal.credential_fence)
                .map_err(|_| runne_provider::CredentialLifecycleError::CorruptState)?,
        ))
    }

    /// Rechecks the store-owned online tuple immediately before native loading.
    /// The durable tuple itself remains sealed inside the binding.
    pub fn validate_online_materialization(
        &self,
        authority: CredentialDispatchAuthority<'_>,
        claim: &ProviderDispatchClaim,
        now: i64,
    ) -> Result<(), runne_provider::CredentialLifecycleError> {
        let Some(seal) = self.1.as_ref() else {
            return Err(runne_provider::CredentialLifecycleError::StaleLease);
        };
        let current = authority
            .store
            .authorize_online_dispatch(authority.launch, claim, now)?;
        if current.matches(seal) {
            Ok(())
        } else {
            Err(runne_provider::CredentialLifecycleError::StaleLease)
        }
    }
}

/// Opaque runtime-owned execution and normalized stream binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderExecutionBinding {
    attempt_id: DispatchAttemptId,
    fencing_token: u64,
    runtime_generation: u64,
    call_digest_version: ProviderCallDigestVersion,
    prepared_digest: [u8; 32],
    profile_digest: [u8; 32],
    stream_id: ProviderStreamId,
}

impl ProviderExecutionBinding {
    pub(super) fn new(
        claim: &ProviderDispatchClaim,
        runtime_generation: u64,
        prepared: PreparedProviderRecord,
        stream_id: ProviderStreamId,
    ) -> Self {
        Self {
            attempt_id: claim.attempt_id,
            fencing_token: claim.fencing_token,
            runtime_generation,
            call_digest_version: prepared.call_digest_version,
            prepared_digest: prepared.prepared_digest,
            profile_digest: prepared.profile_digest,
            stream_id,
        }
    }

    /// Returns the durable provider attempt identity.
    pub const fn attempt_id(&self) -> DispatchAttemptId {
        self.attempt_id
    }

    /// Returns the runtime-issued fencing token.
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }

    /// Returns the runtime generation that admitted the effect.
    pub const fn runtime_generation(&self) -> u64 {
        self.runtime_generation
    }

    /// Returns the exact provider-call digest domain.
    pub const fn call_digest_version(&self) -> ProviderCallDigestVersion {
        self.call_digest_version
    }

    /// Returns the exact credential-free prepared digest.
    pub const fn prepared_digest(&self) -> &[u8; 32] {
        &self.prepared_digest
    }

    /// Returns the exact immutable provider profile digest.
    pub const fn profile_digest(&self) -> &[u8; 32] {
        &self.profile_digest
    }

    /// Returns the normalized adapter stream identity.
    pub const fn stream_id(&self) -> ProviderStreamId {
        self.stream_id
    }

    /// Adds the authoritative active credential lease/fence required by a
    /// versioned provider effect.
    pub fn bind_active_credential(
        self,
        credential: CredentialDispatchBinding,
    ) -> VersionedProviderExecutionBinding {
        VersionedProviderExecutionBinding {
            execution: self,
            credential,
        }
    }
}

/// Provider execution binding that carries only non-secret credential identity
/// and its authoritative active lease/fence tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionedProviderExecutionBinding {
    execution: ProviderExecutionBinding,
    credential: CredentialDispatchBinding,
}

impl VersionedProviderExecutionBinding {
    /// Returns credential-free execution metadata.
    pub const fn execution(&self) -> &ProviderExecutionBinding {
        &self.execution
    }

    /// Returns the non-secret binding for mandatory pre-effect revalidation.
    pub const fn credential_binding(&self) -> &CredentialDispatchBinding {
        &self.credential
    }

    /// Returns the sole cross-layer credential identity.
    pub const fn credential_version_ref(&self) -> &CredentialVersionRef {
        self.credential.version_ref()
    }

    /// Returns the authoritative lease owner.
    pub const fn credential_lease_owner(&self) -> &[u8; 16] {
        self.credential.owner()
    }

    /// Returns the authoritative lease expiry.
    pub const fn credential_lease_expires_at(&self) -> i64 {
        self.credential.expires_at()
    }

    /// Returns the authoritative credential fencing token.
    pub const fn credential_fencing_token(&self) -> u64 {
        self.credential.fencing_token()
    }
}
