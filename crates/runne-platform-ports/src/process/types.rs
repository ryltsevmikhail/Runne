//! Opaque process identities and validated request contracts.
#![allow(clippy::missing_errors_doc)]

/// Closed validation failures for domain-neutral process types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessTypeValidationError {
    EmptyHeldToken,
    /// A held identity version was zero.
    ZeroIdentityVersion,
    /// A file kind or symlink proof did not satisfy the contract.
    InvalidFileProof,
    /// An opaque identity or handle was all zeroes.
    ZeroOpaqueIdentity,
    /// A request digest was all zeroes.
    ZeroRequestDigest,
}

/// Opaque held-file identity with exact validation digests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeldFileIdentityV1 {
    token: [u8; 16],
    canonical_identity_digest: [u8; 32],
    content_digest: [u8; 32],
    filesystem_identity_digest: [u8; 32],
    identity_version: u64,
}

impl HeldFileIdentityV1 {
    pub fn new(
        token: [u8; 16],
        canonical_identity_digest: [u8; 32],
        content_digest: [u8; 32],
        filesystem_identity_digest: [u8; 32],
        identity_version: u64,
    ) -> Result<Self, ProcessTypeValidationError> {
        if token == [0; 16] {
            return Err(ProcessTypeValidationError::EmptyHeldToken);
        }
        if identity_version == 0 {
            return Err(ProcessTypeValidationError::ZeroIdentityVersion);
        }
        Ok(Self {
            token,
            canonical_identity_digest,
            content_digest,
            filesystem_identity_digest,
            identity_version,
        })
    }

    /// Returns the canonical identity digest.
    #[must_use]
    pub const fn canonical_identity_digest(&self) -> &[u8; 32] {
        &self.canonical_identity_digest
    }

    /// Returns the opaque held token for exact contract binding.
    #[must_use]
    pub const fn token(&self) -> &[u8; 16] {
        &self.token
    }

    /// Returns the content digest.
    #[must_use]
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns the filesystem identity digest.
    #[must_use]
    pub const fn filesystem_identity_digest(&self) -> &[u8; 32] {
        &self.filesystem_identity_digest
    }

    /// Returns the identity version.
    #[must_use]
    pub const fn identity_version(&self) -> u64 {
        self.identity_version
    }
}

/// Closed kind proven for a held file identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessFileKindV1 {
    /// A regular file.
    RegularFile,
    /// A directory.
    Directory,
    /// Any other filesystem object.
    Other,
}

/// Closed proof result for a symlink check.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessSymlinkProofV1 {
    /// The identity was proven not to be a symlink.
    VerifiedNotSymlink,
    /// The proof could not be established.
    ProofUnavailable,
    /// The identity was proven to be a symlink.
    IsSymlink,
}

/// Verified executable identity with regular-file and non-symlink proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedExecutableV1 {
    identity: HeldFileIdentityV1,
}

impl VerifiedExecutableV1 {
    pub fn new(
        identity: HeldFileIdentityV1,
        kind: ProcessFileKindV1,
        symlink_proof: ProcessSymlinkProofV1,
    ) -> Result<Self, ProcessTypeValidationError> {
        if kind != ProcessFileKindV1::RegularFile
            || symlink_proof != ProcessSymlinkProofV1::VerifiedNotSymlink
        {
            return Err(ProcessTypeValidationError::InvalidFileProof);
        }
        Ok(Self { identity })
    }

    /// Returns the held executable identity.
    #[must_use]
    pub const fn identity(&self) -> &HeldFileIdentityV1 {
        &self.identity
    }
}

/// Verified working-directory identity with directory and non-symlink proofs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCwdV1 {
    identity: HeldFileIdentityV1,
}

impl VerifiedCwdV1 {
    pub fn new(
        identity: HeldFileIdentityV1,
        kind: ProcessFileKindV1,
        symlink_proof: ProcessSymlinkProofV1,
    ) -> Result<Self, ProcessTypeValidationError> {
        if kind != ProcessFileKindV1::Directory
            || symlink_proof != ProcessSymlinkProofV1::VerifiedNotSymlink
        {
            return Err(ProcessTypeValidationError::InvalidFileProof);
        }
        Ok(Self { identity })
    }

    /// Returns the held working-directory identity.
    #[must_use]
    pub const fn identity(&self) -> &HeldFileIdentityV1 {
        &self.identity
    }
}

macro_rules! opaque_identity {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, Eq, PartialEq)]
        pub struct $name([u8; 16]);

        impl $name {
            /// Creates a non-zero opaque identity.
            ///
            /// # Errors
            /// Returns an error for an all-zero identity.
            pub fn new(value: [u8; 16]) -> Result<Self, ProcessTypeValidationError> {
                if value == [0; 16] {
                    return Err(ProcessTypeValidationError::ZeroOpaqueIdentity);
                }
                Ok(Self(value))
            }

            /// Returns the opaque bytes for exact contract binding.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 16] {
                &self.0
            }
        }
    };
}

opaque_identity!(ProcessOwnerIdV1, "Opaque owner identity.");
opaque_identity!(ProcessAttemptIdV1, "Opaque attempt identity.");
opaque_identity!(ProcessSessionIdV1, "Opaque session identity.");
opaque_identity!(ProcessGenerationIdV1, "Opaque generation identity.");
opaque_identity!(HeldProcessTreeHandleV1, "Opaque held process-tree handle.");

/// Exact lifecycle authority bound to one held process tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessLifecycleBindingV1 {
    owner: ProcessOwnerIdV1,
    attempt: ProcessAttemptIdV1,
    session: ProcessSessionIdV1,
    generation: ProcessGenerationIdV1,
    tree_handle: HeldProcessTreeHandleV1,
}

impl ProcessLifecycleBindingV1 {
    /// Creates a binding from independently typed lifecycle identities.
    #[must_use]
    pub const fn new(
        owner: ProcessOwnerIdV1,
        attempt: ProcessAttemptIdV1,
        session: ProcessSessionIdV1,
        generation: ProcessGenerationIdV1,
        tree_handle: HeldProcessTreeHandleV1,
    ) -> Self {
        Self {
            owner,
            attempt,
            session,
            generation,
            tree_handle,
        }
    }

    /// Returns the exact owner identity.
    #[must_use]
    pub const fn owner(&self) -> &ProcessOwnerIdV1 {
        &self.owner
    }

    /// Returns the exact attempt identity.
    #[must_use]
    pub const fn attempt(&self) -> &ProcessAttemptIdV1 {
        &self.attempt
    }

    /// Returns the exact session identity.
    #[must_use]
    pub const fn session(&self) -> &ProcessSessionIdV1 {
        &self.session
    }

    /// Returns the exact generation identity.
    #[must_use]
    pub const fn generation(&self) -> &ProcessGenerationIdV1 {
        &self.generation
    }

    /// Returns the held process-tree handle.
    #[must_use]
    pub const fn tree_handle(&self) -> &HeldProcessTreeHandleV1 {
        &self.tree_handle
    }
}
