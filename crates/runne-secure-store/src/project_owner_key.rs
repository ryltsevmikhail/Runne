//! Purpose-specific storage API for the one project-owner Ed25519 key.

use ed25519_dalek::{SigningKey, VerifyingKey};
use zeroize::{Zeroize, Zeroizing};

#[path = "project_owner_key/identity_policy.rs"]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod identity_policy;
#[cfg(target_os = "macos")]
#[path = "project_owner_key/macos.rs"]
mod macos;
#[path = "project_owner_key/macos_codec.rs"]
#[allow(dead_code)]
mod macos_codec;
#[cfg(target_os = "macos")]
pub use macos::{CodeSignIdentity, MacosProjectOwnerKeyStore};

/// Maximum accepted transcript size for an owner-key signature operation.
pub const MAX_PROJECT_OWNER_TRANSCRIPT_BYTES: usize = 1_048_576;

/// Public outcome of a project-owner key-store operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreStatus {
    /// The current platform has no permitted project-owner key backend.
    Unsupported,
    /// Required user-presence UI cannot be displayed safely.
    UiUnavailable,
    /// The requested key operation or public binding was denied.
    Denied,
}

/// Exact public identity of one project-owner key epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwnerKeyRef {
    repository_id: String,
    key_epoch: u64,
    public_key: [u8; 32],
}

impl ProjectOwnerKeyRef {
    /// Construct an exact valid project-owner key identity.
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] unless the repository, epoch, and Ed25519 key are valid.
    pub fn new(
        repository_id: impl Into<String>,
        public_key: [u8; 32],
        key_epoch: u64,
    ) -> Result<Self, StoreStatus> {
        let repository_id = repository_id.into();
        if repository_id != "runne" || key_epoch == 0 || !valid_public_key(&public_key) {
            return Err(StoreStatus::Denied);
        }
        Ok(Self {
            repository_id,
            key_epoch,
            public_key,
        })
    }

    /// Return the fixed repository binding.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Return the positive key epoch.
    #[must_use]
    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    /// Return the public Ed25519 key bytes.
    #[must_use]
    pub const fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
}

/// Move-only secret owner seed with its exact public reference.
///
/// ```compile_fail
/// use runne_secure_store::{PendingProjectOwnerKey, ProjectOwnerKeyMaterial};
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<ProjectOwnerKeyMaterial>();
/// needs_clone::<PendingProjectOwnerKey>();
/// ```
///
/// ```compile_fail
/// use std::fmt::Debug;
/// use runne_secure_store::{PendingProjectOwnerKey, ProjectOwnerKeyMaterial};
/// fn needs_debug<T: Debug>() {}
/// needs_debug::<ProjectOwnerKeyMaterial>();
/// needs_debug::<PendingProjectOwnerKey>();
/// ```
///
/// ```compile_fail
/// use serde::Serialize;
/// use runne_secure_store::{PendingProjectOwnerKey, ProjectOwnerKeyMaterial};
/// fn needs_serialize<T: Serialize>() {}
/// needs_serialize::<ProjectOwnerKeyMaterial>();
/// needs_serialize::<PendingProjectOwnerKey>();
/// ```
///
/// ```compile_fail
/// use serde::Deserialize;
/// use runne_secure_store::{PendingProjectOwnerKey, ProjectOwnerKeyMaterial};
/// fn needs_deserialize<'a, T: Deserialize<'a>>() {}
/// needs_deserialize::<ProjectOwnerKeyMaterial>();
/// needs_deserialize::<PendingProjectOwnerKey>();
/// ```
pub struct ProjectOwnerKeyMaterial {
    reference: ProjectOwnerKeyRef,
    seed: Zeroizing<[u8; 32]>,
}

impl ProjectOwnerKeyMaterial {
    /// Create backup-restored material only when its seed derives the supplied exact public key.
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] for invalid identity fields or a seed/public mismatch.
    pub fn from_backup_seed(
        reference: ProjectOwnerKeyRef,
        seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, StoreStatus> {
        let public_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        if public_key != reference.public_key {
            return Err(StoreStatus::Denied);
        }
        Ok(Self { reference, seed })
    }

    /// Return the non-secret public reference.
    #[must_use]
    pub const fn key_ref(&self) -> &ProjectOwnerKeyRef {
        &self.reference
    }

    /// Consume material into the only allowed backup-seed extraction path.
    #[must_use]
    pub fn into_backup_seed(self) -> Zeroizing<[u8; 32]> {
        self.seed
    }
}

/// Pending key record that cannot sign until the native backend activates it.
pub struct PendingProjectOwnerKey {
    reference: ProjectOwnerKeyRef,
    proof_of_possession: [u8; 64],
    token: Zeroizing<[u8; 32]>,
}

impl PendingProjectOwnerKey {
    /// Construct a pending record from native backend-generated state.
    ///
    /// This is a backend SPI for [`ProjectOwnerKeyStore`](crate::ProjectOwnerKeyStore)
    /// implementers only. Construction does not grant activation or signing: the backend must
    /// still compare and set its stored opaque token and exact public reference before activation.
    /// Callers must retain no duplicate of `token` after handing it to this constructor.
    #[doc(hidden)]
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] when the transcript exceeds the protocol limit.
    pub fn from_backend_generated(
        reference: ProjectOwnerKeyRef,
        proof_of_possession: [u8; 64],
        token: Zeroizing<[u8; 32]>,
        transcript: &[u8],
    ) -> Result<Self, StoreStatus> {
        crate::project_owner_key_store::validate_transcript(transcript)?;
        Ok(Self {
            reference,
            proof_of_possession,
            token,
        })
    }

    /// Return the pending key's exact public reference.
    #[must_use]
    pub const fn key_ref(&self) -> &ProjectOwnerKeyRef {
        &self.reference
    }

    /// Return the exact proof generated by the pending key.
    #[must_use]
    pub const fn proof_of_possession(&self) -> [u8; 64] {
        self.proof_of_possession
    }

    /// Constant-time equality check for a backend's stored pending-record token.
    ///
    /// This backend SPI exists only to implement an exact token-and-reference CAS during
    /// activation. It never exposes token bytes, and a match alone grants no capability.
    #[doc(hidden)]
    #[must_use]
    pub fn matches_backend_token(&self, expected: &[u8; 32]) -> bool {
        let difference = self
            .token
            .iter()
            .zip(expected)
            .fold(0_u8, |difference, (actual, expected)| {
                difference | (actual ^ expected)
            });
        difference == 0
    }
}

impl Drop for PendingProjectOwnerKey {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Local anti-rollback floor for one repository's accepted owner trust configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectOwnerAnchorFloor {
    repository_id: String,
    highest_key_epoch: u64,
    accepted_trust_config_sha256: [u8; 32],
}

impl ProjectOwnerAnchorFloor {
    /// Construct a non-empty local owner-trust floor.
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] for an invalid repository, epoch, or empty SHA-256.
    pub fn new(
        repository_id: impl Into<String>,
        highest_key_epoch: u64,
        accepted_trust_config_sha256: [u8; 32],
    ) -> Result<Self, StoreStatus> {
        let repository_id = repository_id.into();
        if repository_id != "runne"
            || highest_key_epoch == 0
            || accepted_trust_config_sha256 == [0; 32]
        {
            return Err(StoreStatus::Denied);
        }
        Ok(Self {
            repository_id,
            highest_key_epoch,
            accepted_trust_config_sha256,
        })
    }

    /// Return the fixed repository binding.
    #[must_use]
    pub fn repository_id(&self) -> &str {
        &self.repository_id
    }

    /// Return the highest accepted key epoch.
    #[must_use]
    pub const fn highest_key_epoch(&self) -> u64 {
        self.highest_key_epoch
    }

    /// Return the pinned canonical trust-configuration digest.
    #[must_use]
    pub const fn accepted_trust_config_sha256(&self) -> [u8; 32] {
        self.accepted_trust_config_sha256
    }
}

fn valid_public_key(bytes: &[u8; 32]) -> bool {
    VerifyingKey::from_bytes(bytes).is_ok_and(|key| !key.is_weak())
}
