use core::fmt;

use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::ProviderId;

mod authority;

pub use authority::{
    CredentialAuthorityPair, CredentialDispatchCapability, CredentialGcClaim,
    CredentialLifecycleAuthority, CredentialNativeCreateAuthorization, CredentialNativeCreateClaim,
    CredentialNativeCreateIssuer, CredentialNativeCreateProgression,
    CredentialNativeCreateValidator, CredentialProvisionSource, NativeCredentialAuthority,
    NativeCredentialDeletionProof,
};

const CREDENTIAL_REF_DOMAIN: &[u8] = b"RUNNE_CREDENTIAL_VERSION_REF_V1\0";

/// Durable non-secret lifecycle state for one native credential version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CredentialVersionState {
    /// SQLite identity exists before native material is created.
    Prepared,
    /// Exactly one version owns current lease-bound provider authority.
    Active,
    /// Provider authority was fenced and the version awaits collection.
    Retired,
    /// Collection owns the version and no new lease may be granted.
    GcClaimed,
    /// Native deletion completed and a permanent tombstone is durable.
    Deleted,
}

/// Sole non-secret credential identity allowed across store/provider layers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialVersionRef {
    provider: ProviderId,
    version: u64,
    ref_digest: [u8; 32],
}

impl CredentialVersionRef {
    /// Constructs a canonical version reference without credential material.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialLifecycleError::InvalidInput`] for version zero.
    pub fn new(provider: ProviderId, version: u64) -> Result<Self, CredentialLifecycleError> {
        if version == 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        let mut hasher = Sha256::new();
        hasher.update(CREDENTIAL_REF_DOMAIN);
        hasher.update((provider.as_str().len() as u64).to_be_bytes());
        hasher.update(provider.as_str().as_bytes());
        hasher.update(version.to_be_bytes());
        Ok(Self {
            provider,
            version,
            ref_digest: hasher.finalize().into(),
        })
    }

    /// Returns the provider identity.
    pub const fn provider(&self) -> &ProviderId {
        &self.provider
    }

    /// Returns the monotonic provider-local version number.
    pub const fn version(&self) -> u64 {
        self.version
    }

    /// Returns the canonical non-secret reference digest.
    pub const fn ref_digest(&self) -> &[u8; 32] {
        &self.ref_digest
    }
}

impl fmt::Debug for CredentialVersionRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialVersionRef")
            .field("provider", &self.provider)
            .field("version", &self.version)
            .field("ref_digest", &"<non-secret-digest>")
            .finish()
    }
}

/// Request to durably reserve a version before native creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrepareCredentialVersion {
    reference: CredentialVersionRef,
}

impl PrepareCredentialVersion {
    /// Constructs a prepared-version request.
    pub const fn new(reference: CredentialVersionRef) -> Self {
        Self { reference }
    }

    /// Returns the requested version reference.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }
}

/// Exact owner, expiry and fence proposed for one active credential lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialLease {
    reference: CredentialVersionRef,
    owner: [u8; 16],
    expires_at: i64,
    fencing_token: u64,
}

impl CredentialLease {
    /// Constructs a non-empty, bounded active lease tuple.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialLifecycleError::InvalidInput`] for zero owner,
    /// non-positive expiry, or zero fencing token.
    pub fn new(
        reference: CredentialVersionRef,
        owner: [u8; 16],
        expires_at: i64,
        fencing_token: u64,
    ) -> Result<Self, CredentialLifecycleError> {
        if owner == [0; 16] || expires_at <= 0 || fencing_token == 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        Ok(Self {
            reference,
            owner,
            expires_at,
            fencing_token,
        })
    }

    /// Returns the credential version.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }

    /// Returns the authoritative lease owner.
    pub const fn owner(&self) -> &[u8; 16] {
        &self.owner
    }

    /// Returns the absolute lease expiry.
    pub const fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Returns the non-zero fencing token.
    pub const fn fencing_token(&self) -> u64 {
        self.fencing_token
    }
}

/// Revocation request whose fence must cover active provider authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevokeCredentialVersion {
    reference: CredentialVersionRef,
    revocation_fence: u64,
}

impl RevokeCredentialVersion {
    /// Constructs a non-zero revocation fence.
    ///
    /// # Errors
    ///
    /// Returns [`CredentialLifecycleError::InvalidInput`] for fence zero.
    pub fn new(
        reference: CredentialVersionRef,
        revocation_fence: u64,
    ) -> Result<Self, CredentialLifecycleError> {
        if revocation_fence == 0 {
            return Err(CredentialLifecycleError::InvalidInput);
        }
        Ok(Self {
            reference,
            revocation_fence,
        })
    }

    /// Returns the credential version.
    pub const fn version_ref(&self) -> &CredentialVersionRef {
        &self.reference
    }

    /// Returns the authoritative revocation fence.
    pub const fn revocation_fence(&self) -> u64 {
        self.revocation_fence
    }
}

/// Idempotent reconciliation work that still requires native deletion.
#[derive(Debug, Default)]
pub struct ReconcileCredentialVersions {
    native_deletions: Vec<CredentialGcClaim>,
}

impl ReconcileCredentialVersions {
    /// Constructs store-owned native deletion work.
    #[doc(hidden)]
    pub fn new(native_deletions: Vec<CredentialGcClaim>) -> Self {
        Self { native_deletions }
    }

    /// Returns every `GC_CLAIMED` version awaiting idempotent native delete.
    pub fn native_deletions(&self) -> &[CredentialGcClaim] {
        &self.native_deletions
    }

    /// Consumes the reconciliation batch into exclusive native delete claims.
    pub fn into_native_deletions(self) -> Vec<CredentialGcClaim> {
        self.native_deletions
    }
}

/// Closed credential lifecycle failure vocabulary with no secret context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum CredentialLifecycleError {
    /// Input violates a public bound.
    #[error("credential lifecycle input is invalid")]
    InvalidInput,
    /// Durable state could not be read or committed.
    #[error("credential lifecycle store is unavailable")]
    StoreUnavailable,
    /// The requested version does not exist.
    #[error("credential version was not found")]
    NotFound,
    /// Another version or lease won the compare-and-set.
    #[error("credential lifecycle compare-and-set conflict")]
    Conflict,
    /// The requested lifecycle is terminal for this operation.
    #[error("credential lifecycle is closed")]
    LifecycleClosed,
    /// Lease owner, expiry, or fencing token is no longer authoritative.
    #[error("credential lease or fence is stale")]
    StaleLease,
    /// Durable row content does not match the canonical reference.
    #[error("credential lifecycle state is corrupt")]
    CorruptState,
}

/// Durable provider credential lifecycle authority.
pub trait ProviderCredentialVersionStore: Send + Sync {
    /// Creates or exactly replays durable `PREPARED` identity.
    fn create_prepared(
        &self,
        input: PrepareCredentialVersion,
    ) -> Result<CredentialVersionRef, CredentialLifecycleError>;

    /// Grants the sole active lease by transactional compare-and-set.
    fn activate(
        &self,
        lease: CredentialLease,
    ) -> Result<CredentialVersionRef, CredentialLifecycleError>;

    /// Durably fences provider authority before any later provider effect.
    fn revoke_and_fence(
        &self,
        input: RevokeCredentialVersion,
    ) -> Result<(), CredentialLifecycleError>;

    /// Claims collectible versions and returns idempotent native delete work.
    fn reconcile(&self, now: i64) -> Result<ReconcileCredentialVersions, CredentialLifecycleError>;
}
