use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::credential::enrollment::{CredentialBindingDigest, CredentialEnrollmentError};

const GRANT_DOMAIN: &[u8] = b"gocode/macos-credential-service/mutation-grant/v1\0";

/// Current, random service instance identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CredentialServiceEpoch([u8; 16]);

impl CredentialServiceEpoch {
    /// Validates the non-zero 128-bit epoch emitted by the service.
    pub fn from_bytes(value: [u8; 16]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 16] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }
    /// Returns the fixed-width non-secret epoch.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Monotonic service request sequence scoped to one authenticated session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialServiceRequestSequence(u64);

impl CredentialServiceRequestSequence {
    /// Validates a non-zero sequence.
    pub fn new(value: u64) -> Result<Self, CredentialEnrollmentError> {
        if value == 0 {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }
    /// Returns the sequence value.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Unpredictable request correlation bound inside the canonical provider frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CredentialServiceCorrelation([u8; 16]);

impl CredentialServiceCorrelation {
    /// Validates a non-zero correlation identity.
    pub fn from_bytes(value: [u8; 16]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 16] {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }

    /// Returns the fixed-width non-secret identity.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// Issued and expiry timestamps for a bounded service request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialServiceDeadline {
    issued_at_unix_millis: u64,
    expires_at_unix_millis: u64,
}

impl CredentialServiceDeadline {
    /// Maximum mutation or read request lifetime in milliseconds.
    pub const MAX_LIFETIME_MILLIS: u64 = 30_000;
    /// Validates a non-zero, overflow-safe lifetime of at most thirty seconds.
    pub fn new(issued: u64, expires: u64) -> Result<Self, CredentialEnrollmentError> {
        let lifetime = expires
            .checked_sub(issued)
            .ok_or(CredentialEnrollmentError::InvalidInput)?;
        if issued == 0 || lifetime == 0 || lifetime > Self::MAX_LIFETIME_MILLIS {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self {
            issued_at_unix_millis: issued,
            expires_at_unix_millis: expires,
        })
    }
    /// Rejects a request whose expiry outlives its protected parent session.
    pub fn verify_parent_expiry(
        self,
        parent_expires_at_unix_millis: u64,
    ) -> Result<Self, CredentialEnrollmentError> {
        if self.expires_at_unix_millis > parent_expires_at_unix_millis {
            return Err(CredentialEnrollmentError::InvalidEvidence);
        }
        Ok(self)
    }
    /// Returns the issue timestamp.
    pub const fn issued_at_unix_millis(self) -> u64 {
        self.issued_at_unix_millis
    }
    /// Returns the expiry timestamp.
    pub const fn expires_at_unix_millis(self) -> u64 {
        self.expires_at_unix_millis
    }
}

/// Digest-only identity of a move-only mutation grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialMutationGrantDigest(CredentialBindingDigest);

impl CredentialMutationGrantDigest {
    /// Admits a non-secret digest measured by the authenticated handoff path.
    pub const fn from_measurement(value: CredentialBindingDigest) -> Self {
        Self(value)
    }
    /// Returns the measured digest used in the runtime arm transcript.
    pub const fn binding_digest(self) -> CredentialBindingDigest {
        self.0
    }
}

/// Opaque, zeroizing 256-bit one-use mutation grant.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialMutationGrant>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialMutationGrant>();
/// ```
/// ```compile_fail
/// fn needs_serialize<T: serde::Serialize>() {}
/// needs_serialize::<runne_provider::CredentialMutationGrant>();
/// ```
/// ```compile_fail
/// fn needs_deserialize<T: serde::Deserialize<'static>>() {}
/// needs_deserialize::<runne_provider::CredentialMutationGrant>();
/// ```
pub struct CredentialMutationGrant(Zeroizing<[u8; 32]>);

impl CredentialMutationGrant {
    /// Generates one fresh grant using the operating-system CSPRNG.
    pub fn generate() -> Result<Self, CredentialEnrollmentError> {
        let mut value = Zeroizing::new([0_u8; 32]);
        rand::rngs::OsRng
            .try_fill_bytes(value.as_mut())
            .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?;
        if value.as_ref() == [0; 32] {
            return Err(CredentialEnrollmentError::EntropyUnavailable);
        }
        Ok(Self(value))
    }
    /// Returns the non-secret digest for the runtime arm transcript.
    pub fn digest(&self) -> CredentialMutationGrantDigest {
        let mut hasher = Sha256::new();
        hasher.update(GRANT_DOMAIN);
        hasher.update(self.0.as_slice());
        CredentialMutationGrantDigest::from_measurement(
            CredentialBindingDigest::from_measured(hasher.finalize().into())
                .expect("sha256 is non-zero"),
        )
    }
    pub(super) fn from_wire(mut value: [u8; 32]) -> Result<Self, CredentialEnrollmentError> {
        if value == [0; 32] {
            return Err(CredentialEnrollmentError::InvalidFrame);
        }
        let grant = Self(Zeroizing::new(value));
        value.zeroize();
        Ok(grant)
    }
    pub(super) fn wire_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Bounded, zeroizing credential material carried only on writer/read-use paths.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<runne_provider::CredentialMaterial>();
/// ```
/// ```compile_fail
/// fn needs_debug<T: core::fmt::Debug>() {}
/// needs_debug::<runne_provider::CredentialMaterial>();
/// ```
/// ```compile_fail
/// fn needs_serialize<T: serde::Serialize>() {}
/// needs_serialize::<runne_provider::CredentialMaterial>();
/// ```
/// ```compile_fail
/// fn needs_deserialize<T: serde::Deserialize<'static>>() {}
/// needs_deserialize::<runne_provider::CredentialMaterial>();
/// ```
pub struct CredentialMaterial(Zeroizing<Vec<u8>>);

impl CredentialMaterial {
    /// Maximum permitted credential material bytes.
    pub const MAX_BYTES: usize = 4096;
    /// Validates bounded non-empty material at the live secret boundary.
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, CredentialEnrollmentError> {
        Self::from_zeroizing(Zeroizing::new(value))
    }
    pub(crate) fn from_zeroizing(
        value: Zeroizing<Vec<u8>>,
    ) -> Result<Self, CredentialEnrollmentError> {
        if value.is_empty() || value.len() > Self::MAX_BYTES {
            return Err(CredentialEnrollmentError::InvalidInput);
        }
        Ok(Self(value))
    }
    /// Consumes plaintext only inside the provider-effect callback.
    pub fn consume(self, callback: impl FnOnce(&[u8])) {
        callback(&self.0);
    }
    pub(super) fn wire_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
    pub(super) fn from_wire(value: Vec<u8>) -> Result<Self, CredentialEnrollmentError> {
        Self::from_bytes(value).map_err(|_| CredentialEnrollmentError::InvalidFrame)
    }
}

/// Receipt proving an active dispatch crossed the effect-start boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialDispatchEffectReceipt(CredentialBindingDigest);

impl CredentialDispatchEffectReceipt {
    pub(crate) const fn from_trusted_effect_start(value: CredentialBindingDigest) -> Self {
        Self(value)
    }
    pub(super) const fn from_wire(value: CredentialBindingDigest) -> Self {
        Self(value)
    }
    /// Returns the non-secret receipt digest.
    pub const fn digest(self) -> CredentialBindingDigest {
        self.0
    }
}

/// Code-owned endpoint role; it is never caller-supplied text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialServiceEndpointRole {
    /// Registration and challenge listener.
    Desktop,
    /// Authenticated runtime arm/read listener.
    Runtime,
    /// Authenticated one-use writer listener.
    Writer,
}

/// Closed service outcome that cannot be widened by an adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialServiceDisposition {
    /// Session loss requires reconciliation and never permits blind mutation retry.
    SessionMissing {
        /// Current service epoch used only for bounded reconciliation/rejoin.
        current_epoch: CredentialServiceEpoch,
    },
    /// The request was stale, replayed, expired, or denied.
    Denied,
    /// The service cannot presently perform the request.
    Unavailable,
    /// The platform capability is unsupported.
    Unsupported,
    /// A post-effect outcome requires runtime reconciliation.
    Uncertain,
}

impl CredentialServiceDisposition {
    /// Returns true only for outcomes whose next legal step is reconciliation.
    pub const fn requires_reconciliation(self) -> bool {
        matches!(self, Self::SessionMissing { .. } | Self::Uncertain)
    }
}
