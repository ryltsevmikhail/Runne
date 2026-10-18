use runne_api::ApiPrincipalId;
use runne_application::{
    permission_modes::{PermissionModeError, PermissionScope},
    project_trust::{ProjectTrustEffectLease, ProjectTrustProjectId, ProjectTrustStatus},
};
use runne_domain::id::{CommandId, IdempotencyKey, IntegrityDigest, validate_uuid_v7_bytes};
use rusqlite::Error as SqliteError;

pub use super::managed_identity::{
    ClosedRulesManagedIdentityV2, LegacyRecordIdentityV1, ManagedIdentityChallengeBindingV2,
    ManagedIdentityMetadata, PermissionModeSelectionManagedIdentity,
};

mod challenge;
pub use challenge::*;
mod confirmation_v2;
pub use confirmation_v2::*;

/// Store-specific failure at the durable permission-mode boundary.
#[derive(Debug, thiserror::Error)]
pub enum PermissionModeStoreError {
    /// The application command was rejected by its frozen semantic contract.
    #[error(transparent)]
    Command(#[from] PermissionModeError),
    /// The principal does not own a canonical, live, open workspace.
    #[error("permission mode workspace is unavailable")]
    ScopeUnavailable,
    /// The authenticated principal or Store authority did not match the command.
    #[error("permission mode authority does not match")]
    AuthorityMismatch,
    /// The current T1 record does not match the command's managed snapshot.
    #[error("permission mode managed policy is stale")]
    ManagedPolicyStale,
    /// A fresh full-access challenge cannot be issued or consumed.
    #[error("full-access native challenge is unavailable")]
    ReauthenticationUnavailable,
    /// SQLite or its durable identity metadata is unavailable.
    #[error("permission mode Store is unavailable")]
    Unavailable,
    /// Persisted permission-mode state failed exact validation.
    #[error("permission mode Store data is corrupt")]
    CorruptData,
}

impl From<SqliteError> for PermissionModeStoreError {
    fn from(_: SqliteError) -> Self {
        Self::Unavailable
    }
}

/// Canonical full-access mode-change fields before the Store issues a nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullAccessChallengeRequest {
    /// Stable command ID reserved for the eventual mode change.
    pub command_id: CommandId,
    /// Stable idempotency key reserved for the eventual mode change.
    pub idempotency_key: IdempotencyKey,
    /// Runtime authority, authenticated principal, and workspace scope.
    pub scope: PermissionScope,
    /// Mode revision shown by the native warning.
    pub expected_authorization_revision: u64,
    /// The optional lifetime selected for the full-access mode itself.
    pub mode_expires_at_unix_ms: Option<i64>,
}

/// Durable mode selection plus the managed snapshot it was checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionModeSelectionSnapshot {
    pub selection: runne_application::permission_modes::ModeSelection,
    pub managed_policy_version: u64,
    pub managed_policy_digest: IntegrityDigest,
}

/// Identity of the existing protected native launch that owns the signer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtectedNativeLaunchContext {
    launch_authority_id: [u8; 16],
    desktop_host_instance_id: [u8; 16],
    daemon_instance_id: [u8; 16],
    launch_generation: u64,
    key_epoch: u64,
    protected_session_id: Option<[u8; 16]>,
}

impl ProtectedNativeLaunchContext {
    /// Builds a typed context from the current protected launch owner.
    pub fn new(
        launch_authority_id: [u8; 16],
        desktop_host_instance_id: [u8; 16],
        daemon_instance_id: [u8; 16],
        launch_generation: u64,
        key_epoch: u64,
    ) -> Result<Self, PermissionModeStoreError> {
        if launch_authority_id.iter().all(|byte| *byte == 0)
            || desktop_host_instance_id.iter().all(|byte| *byte == 0)
            || daemon_instance_id.iter().all(|byte| *byte == 0)
            || launch_generation == 0
            || key_epoch == 0
            || i64::try_from(launch_generation).is_err()
            || i64::try_from(key_epoch).is_err()
        {
            return Err(PermissionModeStoreError::ReauthenticationUnavailable);
        }
        Ok(Self {
            launch_authority_id,
            desktop_host_instance_id,
            daemon_instance_id,
            launch_generation,
            key_epoch,
            protected_session_id: None,
        })
    }

    /// Binds this protected launch context to its current UUIDv7 session.
    /// The legacy `new` constructor remains sessionless for V1 callers.
    pub fn with_protected_session_id(
        mut self,
        protected_session_id: [u8; 16],
    ) -> Result<Self, PermissionModeStoreError> {
        validate_uuid_v7_bytes(&protected_session_id)
            .map_err(|_| PermissionModeStoreError::ReauthenticationUnavailable)?;
        self.protected_session_id = Some(protected_session_id);
        Ok(self)
    }

    pub const fn launch_authority_id(&self) -> &[u8; 16] {
        &self.launch_authority_id
    }

    pub const fn desktop_host_instance_id(&self) -> &[u8; 16] {
        &self.desktop_host_instance_id
    }

    pub const fn daemon_instance_id(&self) -> &[u8; 16] {
        &self.daemon_instance_id
    }

    pub const fn launch_generation(&self) -> u64 {
        self.launch_generation
    }

    pub const fn key_epoch(&self) -> u64 {
        self.key_epoch
    }

    pub const fn protected_session_id(&self) -> Option<&[u8; 16]> {
        self.protected_session_id.as_ref()
    }
}

/// T1 lease and authenticated ingress context held through the Store commit.
///
/// The caller acquires this T1 effect lease before entering the Store. Keeping
/// the borrowed lease in this value preserves the lock order: trust, Store,
/// then the managed-area root.
pub struct PermissionModeAuthorityContext<'a> {
    pub(crate) authenticated_principal: &'a ApiPrincipalId,
    pub(crate) trust_project_id: ProjectTrustProjectId,
    pub(crate) trust_lease: &'a dyn ProjectTrustEffectLease,
    pub(crate) native_launch: Option<&'a ProtectedNativeLaunchContext>,
}

impl<'a> PermissionModeAuthorityContext<'a> {
    /// Creates an operation context from trusted ingress and the held T1 lease.
    pub fn new(
        authenticated_principal: &'a ApiPrincipalId,
        trust_project_id: ProjectTrustProjectId,
        trust_lease: &'a dyn ProjectTrustEffectLease,
        native_launch: Option<&'a ProtectedNativeLaunchContext>,
    ) -> Self {
        Self {
            authenticated_principal,
            trust_project_id,
            trust_lease,
            native_launch,
        }
    }
}

/// Identity and revision captured from the current T1 effect lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ManagedSnapshot {
    pub(crate) project_id: ProjectTrustProjectId,
    pub(crate) instance_epoch: u64,
    pub(crate) revision: u64,
    pub(crate) status: ProjectTrustStatus,
    pub(crate) deny_mask: u32,
    pub(crate) digest: IntegrityDigest,
}
