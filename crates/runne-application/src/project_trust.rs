//! Project Trust Gate domain types and ports (T1).
//!
//! Two explicitly separated admission stages under one policy authority
//! (frozen inventory §F/S2): pre-read `admit_source` over source metadata
//! only, and byte-level `inspect` on the existing prohibited-content
//! boundary. No client-supplied trusted flag exists in this contract: trust
//! state is runtime-owned and durable.
//!
//! ABA safety (F1): every durable sidecar owns an unpredictable instance
//! epoch created once from the OS CSPRNG. Revision numbers are only unique
//! inside one epoch, so every observation and every CAS commit carries the
//! full `TrustToken { instance_epoch, revision }`. A deleted and recreated
//! sidecar gets a fresh epoch: old tokens are foreign by construction and
//! can neither admit sources nor commit state.

use thiserror::Error;

mod persistence;
pub use persistence::{ProjectTrustControlLease, ProjectTrustEffectLease, ProjectTrustPersistence};

/// Frozen deny-policy version implemented by `runne-security`.
/// Policy revision 2 (2026-09-19): Unicode case-mapped over-deny keys, the
/// extended frozen deny set (OpenSSH defaults, `.git-credentials`, dotenv
/// family prefix) and trailing-dot/space rejection. See
/// docs/05-security/T1_SOURCE_PATH_INVENTORY.md §G3 revision history.
pub const FROZEN_POLICY_VERSION: u64 = 2;

/// Policy generation for the separately admitted TaskRun local-command action.
pub const LOCAL_COMMAND_POLICY_VERSION: u64 = 1;

/// Stable identifier of a project inside the trust store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ProjectTrustProjectId([u8; 16]);

impl ProjectTrustProjectId {
    /// Wraps 16 raw bytes.
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw identifier bytes.
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Runtime-owned project trust state (plan 18 §T1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectTrustStatus {
    /// Default. No project-controlled source may be admitted.
    Untrusted,
    /// Project verified; per-path frozen deny policy still applies.
    Trusted,
    /// Verified policy authority; managed deny is never lifted by mode.
    Managed,
}

/// Full durable observation token: epoch-scoped revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustToken {
    /// Unpredictable sidecar instance epoch (CSPRNG, not wall clock).
    pub instance_epoch: u64,
    /// Monotonic revision inside the epoch; `0` means "no durable row yet".
    pub revision: u64,
}

impl TrustToken {
    /// Builds a token.
    pub const fn new(instance_epoch: u64, revision: u64) -> Self {
        Self {
            instance_epoch,
            revision,
        }
    }
}

/// Durable trust record of one project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectTrustRecord {
    /// Current status.
    pub status: ProjectTrustStatus,
    /// Instance epoch owning `revision`.
    pub instance_epoch: u64,
    /// Monotonic CAS revision; `0` means "no durable row yet".
    pub revision: u64,
    /// Managed per-channel deny mask (bit per `SourceChannel`).
    pub managed_deny_mask: u32,
}

impl ProjectTrustRecord {
    /// Fail-closed default for projects without a durable row, bound to the
    /// current sidecar instance epoch (F1: absent records are epoch-scoped).
    pub const fn untrusted_default(instance_epoch: u64) -> Self {
        Self {
            status: ProjectTrustStatus::Untrusted,
            instance_epoch,
            revision: 0,
            managed_deny_mask: 0,
        }
    }

    /// The observation token carried by this record.
    pub const fn token(&self) -> TrustToken {
        TrustToken::new(self.instance_epoch, self.revision)
    }
}

/// Project-controlled ingestion channels (frozen inventory §A/§B).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceChannel {
    /// Instruction files. Unavailable until T1 PASS.
    Instructions,
    /// Skills. Unavailable until T1 PASS.
    Skills,
    /// Hooks. Unavailable until T1 PASS.
    Hooks,
    /// Helpers. Unavailable until T1 PASS.
    Helpers,
    /// Local MCP roots. Unavailable until T1 PASS.
    McpLocal,
    /// Workspace file listing; the path is optional (root listing).
    FilesList,
    /// Workspace file read; the path is mandatory (F3).
    FilesRead,
}

impl SourceChannel {
    /// Stable bit index used by `managed_deny_mask`.
    pub const fn mask_bit(self) -> u32 {
        match self {
            Self::Instructions => 1 << 0,
            Self::Skills => 1 << 1,
            Self::Hooks => 1 << 2,
            Self::Helpers => 1 << 3,
            Self::McpLocal => 1 << 4,
            Self::FilesList => 1 << 5,
            Self::FilesRead => 1 << 6,
        }
    }

    /// Whether the channel has an activation gate wired today.
    ///
    /// Decision (T1 slice): these channels stay unavailable regardless of
    /// trust status until their activation gates exist; admitting them is a
    /// typed deny, not a silent allowance.
    pub const fn activation_gated(self) -> bool {
        matches!(
            self,
            Self::Instructions | Self::Skills | Self::Hooks | Self::Helpers | Self::McpLocal
        )
    }
}

/// Permission mode claim supplied by the caller.
///
/// Managed deny is never lifted by any mode (plan 18 §T1); the value exists
/// in the contract only so this invariant is testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionMode {
    /// Ask for permission.
    Ask,
    /// Confirm on behalf of the user.
    ConfirmForMe,
    /// Full access.
    FullAccess,
}

/// Why a source admission was denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SourceDenyReason {
    /// Project is untrusted.
    #[error("project trust status is untrusted")]
    Untrusted,
    /// Channel-level managed deny.
    #[error("channel denied by managed policy")]
    ManagedDeny,
    /// Path matched the frozen deny set.
    #[error("path matched the frozen deny policy")]
    SensitivePath,
    /// Channel has no activation gate yet.
    #[error("channel unavailable until activation gate exists")]
    ChannelUnavailable,
}

/// Typed fail-closed admission errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrustAdmissionError {
    /// Denied by policy; carries the exact reason.
    #[error("source admission denied: {reason}")]
    DeniedByPolicy {
        /// Exact deny reason.
        reason: SourceDenyReason,
    },
    /// Caller observed a stale revision inside the current epoch.
    #[error("stale trust revision: observed {observed}, current {current}")]
    StaleRevision {
        /// Revision the caller observed.
        observed: u64,
        /// Current durable revision.
        current: u64,
    },
    /// Caller token belongs to a foreign (e.g. deleted) sidecar epoch.
    #[error("foreign trust instance epoch: observed {observed_epoch}, current {current_epoch}")]
    ForeignEpoch {
        /// Epoch the caller observed.
        observed_epoch: u64,
        /// Current durable epoch.
        current_epoch: u64,
    },
    /// A mandatory source path is missing (F3).
    #[error("channel requires an explicit source path")]
    MissingPath,
    /// Path is ambiguous and rejected before any comparison.
    #[error("ambiguous source path rejected")]
    AmbiguousPath,
    /// Policy authority or its durable state cannot be consulted.
    #[error("trust policy authority unavailable")]
    AuthorityUnavailable,
}

/// Successful pre-read admission of one source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAdmission {
    /// Durable trust token observed at admission.
    pub token: TrustToken,
    /// Frozen deny-policy version that decided this admission.
    pub policy_version: u64,
}

/// Admission tuple for the additive local-command action. Source admission
/// remains pinned to the frozen source policy while this action has its own
/// versioned approval policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalCommandAdmission {
    /// Current epoch-scoped trust record.
    pub token: TrustToken,
    /// Existing frozen source policy generation, always version 2 here.
    pub source_policy_version: u64,
    /// Dedicated local-command policy generation.
    pub command_policy_version: u64,
}

/// Stage-1 admission request: metadata only, never content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceAdmissionRequest<'a> {
    /// Channel the source belongs to.
    pub channel: SourceChannel,
    /// Workspace-relative path; mandatory for path-shaped channels (F3).
    pub path: Option<&'a str>,
    /// Full epoch-scoped token the caller observed, if any.
    pub observed_token: Option<TrustToken>,
    /// Caller permission mode claim; never lifts managed deny.
    pub permission_mode: PermissionMode,
}

/// Durable persistence failure modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TrustPersistenceError {
    /// CAS conflict inside the current epoch: the row moved.
    #[error("trust revision conflict: expected revision {expected}, current {current}")]
    Conflict {
        /// Revision the commit expected.
        expected: u64,
        /// Revision currently durable.
        current: u64,
    },
    /// CAS token names a foreign sidecar epoch; stale grants cannot write
    /// into a recreated store (F1).
    #[error("foreign trust instance epoch: expected {expected_epoch}, current {current_epoch}")]
    ForeignEpoch {
        /// Epoch the commit expected.
        expected_epoch: u64,
        /// Current durable epoch.
        current_epoch: u64,
    },
    /// Store is unavailable, unverified or corrupt; fail closed.
    #[error("trust persistence unavailable")]
    Unavailable,
}
