use runne_application::permission_modes::PermissionScope;
use runne_application::project_trust::ProjectTrustStatus;
use runne_domain::id::{CommandId, EventLogLineageId, IdempotencyKey, IntegrityDigest, ProjectId};

use super::ProtectedNativeLaunchContext;

/// Store-issued full-access challenge data for the protected native host.
///
/// `nonce_for_native_signing` is for trusted local host code only. This type
/// has no serialization implementation and its Debug output omits the nonce.
#[derive(Clone, PartialEq, Eq)]
pub struct IssuedFullAccessChallenge {
    pub(crate) challenge_id: [u8; 16],
    pub(crate) nonce: [u8; 32],
    pub(crate) challenge_binding_digest: IntegrityDigest,
    pub(crate) expires_at_unix_ms: i64,
    pub(crate) native_warning_version: u16,
    pub(crate) context: IssuedFullAccessChallengeContext,
}

/// Exact Store-owned outer context delivered only to trusted native signing code.
/// It has no serialization implementation and contains no proof or nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedFullAccessChallengeContext {
    pub(crate) command_id: CommandId,
    pub(crate) idempotency_key: IdempotencyKey,
    pub(crate) scope: PermissionScope,
    pub(crate) expected_authorization_revision: u64,
    pub(crate) project_id: ProjectId,
    pub(crate) project_version: u64,
    pub(crate) workspace_version: u64,
    pub(crate) store_authority_id: [u8; 16],
    pub(crate) store_lineage_id: EventLogLineageId,
    pub(crate) managed_instance_epoch: u64,
    pub(crate) managed_policy_revision: u64,
    pub(crate) managed_status: ProjectTrustStatus,
    pub(crate) managed_deny_mask: u32,
    pub(crate) managed_policy_digest: IntegrityDigest,
    pub(crate) mode_expires_at_unix_ms: Option<i64>,
    pub(crate) native_launch: ProtectedNativeLaunchContext,
}

impl IssuedFullAccessChallengeContext {
    /// Stable ID reserved for the eventual command.
    pub const fn command_id(&self) -> CommandId {
        self.command_id
    }
    /// Stable idempotency identity reserved for the eventual command.
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }
    /// Exact authenticated runtime/principal/workspace boundary.
    pub const fn scope(&self) -> &PermissionScope {
        &self.scope
    }
    /// Mode revision shown by the native warning.
    pub const fn expected_authorization_revision(&self) -> u64 {
        self.expected_authorization_revision
    }
    /// Actual canonical Project that owns the workspace.
    pub const fn project_id(&self) -> ProjectId {
        self.project_id
    }
    /// Current Project version at challenge issuance.
    pub const fn project_version(&self) -> u64 {
        self.project_version
    }
    /// Current Workspace version at challenge issuance.
    pub const fn workspace_version(&self) -> u64 {
        self.workspace_version
    }
    /// Existing canonical database authority identity.
    pub const fn store_authority_id(&self) -> &[u8; 16] {
        &self.store_authority_id
    }
    /// Existing event-log lineage identity.
    pub const fn store_lineage_id(&self) -> EventLogLineageId {
        self.store_lineage_id
    }
    /// T1 sidecar instance epoch captured under the effect lease.
    pub const fn managed_instance_epoch(&self) -> u64 {
        self.managed_instance_epoch
    }
    /// T1 record revision, which is the app command's managed-policy version.
    pub const fn managed_policy_revision(&self) -> u64 {
        self.managed_policy_revision
    }
    /// T1 trust/managed state captured under the effect lease.
    pub const fn managed_status(&self) -> ProjectTrustStatus {
        self.managed_status
    }
    /// T1 managed deny mask captured under the effect lease.
    pub const fn managed_deny_mask(&self) -> u32 {
        self.managed_deny_mask
    }
    /// Semantic digest of the exact current T1 record and Project ID.
    pub const fn managed_policy_digest(&self) -> IntegrityDigest {
        self.managed_policy_digest
    }
    /// Optional lifetime of the selected mode grant.
    pub const fn mode_expires_at_unix_ms(&self) -> Option<i64> {
        self.mode_expires_at_unix_ms
    }
    /// Protected native signer ownership captured at issuance.
    pub const fn native_launch(&self) -> &ProtectedNativeLaunchContext {
        &self.native_launch
    }
}

impl IssuedFullAccessChallenge {
    /// Store-issued opaque identity included in the signed challenge transcript.
    pub const fn challenge_id(&self) -> &[u8; 16] {
        &self.challenge_id
    }

    /// Store-derived exact context required by the trusted native MAC transcript.
    pub const fn context(&self) -> &IssuedFullAccessChallengeContext {
        &self.context
    }

    /// Purpose-bound nonce passed only to the protected native signer.
    pub const fn nonce_for_native_signing(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Digest copied into the eventual command and native proof binding.
    pub const fn challenge_binding_digest(&self) -> IntegrityDigest {
        self.challenge_binding_digest
    }

    /// Store-selected finite expiry of this challenge.
    pub const fn expires_at_unix_ms(&self) -> i64 {
        self.expires_at_unix_ms
    }

    /// Version of the native warning text bound by the Store.
    pub const fn native_warning_version(&self) -> u16 {
        self.native_warning_version
    }
}

impl std::fmt::Debug for IssuedFullAccessChallenge {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IssuedFullAccessChallenge")
            .field("challenge_id", &self.challenge_id)
            .field("nonce", &"<redacted>")
            .field("challenge_binding_digest", &self.challenge_binding_digest)
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .field("native_warning_version", &self.native_warning_version)
            .finish()
    }
}
