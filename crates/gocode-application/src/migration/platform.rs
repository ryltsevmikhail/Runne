//! Exact platform certification contracts.

use gocode_domain::timestamp::Timestamp;

use super::{
    gates::{GateContext, GateEvidence},
    types::{ArtifactDigest, GateId},
};

/// Operating-system identity used by platform certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformOs {
    /// Linux platform.
    Linux,
    /// Apple macOS platform.
    MacOs,
    /// Microsoft Windows platform.
    Windows,
    /// Closed extension value that must still match exactly.
    Other(String),
}

/// Processor architecture used by platform certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformArchitecture {
    /// 64-bit Arm.
    Aarch64,
    /// 64-bit x86.
    X86_64,
    /// Closed extension value that must still match exactly.
    Other(String),
}

/// Storage filesystem class used by platform certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemClass {
    /// Local durable filesystem with governed sync semantics.
    LocalDurable,
    /// Network or remote filesystem.
    Network,
    /// Closed extension value that must still match exactly.
    Other(String),
}

/// SQLite or platform VFS identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformVfs {
    /// SQLite default VFS for the exact certified platform.
    SqliteDefault,
    /// Apple VFS profile with full filesystem synchronization.
    AppleFullFsync,
    /// Closed extension value that must still match exactly.
    Other(String),
}

/// Process containment model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessModel {
    /// POSIX process model.
    Posix,
    /// Windows process model.
    Windows,
    /// Explicit sandboxed process model.
    Sandboxed,
    /// Closed extension value that must still match exactly.
    Other(String),
}

/// Exact platform tuple covered by one certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformTuple {
    /// Operating system.
    pub os: PlatformOs,
    /// Processor architecture.
    pub architecture: PlatformArchitecture,
    /// Filesystem class.
    pub filesystem: FilesystemClass,
    /// Exact platform VFS.
    pub vfs: PlatformVfs,
    /// Process containment model.
    pub process_model: ProcessModel,
    /// Exact sandbox profile artifact.
    pub sandbox_profile_digest: ArtifactDigest,
}

/// Request to evaluate an exact tuple for an exact migration scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformCertificationRequest {
    /// Attempted exact platform tuple.
    pub platform: PlatformTuple,
    /// Gate identity used in emitted evidence.
    pub gate_id: GateId,
    /// Gate contract revision.
    pub gate_revision: u16,
    /// Exact runtime, cohort and artifact scope.
    pub context: GateContext,
    /// Last instant at which emitted evidence remains valid.
    pub valid_until: Timestamp,
    /// Digest of the canonical certification artifact.
    pub evidence_digest: ArtifactDigest,
}

/// Exact platform certification authority.
pub trait PlatformCertificationPort {
    /// Certify a request or fail without widening any tuple field.
    fn certify(
        &self,
        request: PlatformCertificationRequest,
    ) -> Result<GateEvidence, PlatformCertificationError>;
}

/// Closed platform certification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformCertificationError {
    /// Attempted tuple is not exactly certified.
    TupleNotCertified,
    /// Tuple contains an invalid closed extension value.
    InvalidTuple,
    /// Gate revision is zero or validity window is empty.
    InvalidEvidenceWindow,
    /// Certification artifact digest is the all-zero sentinel.
    EmptyEvidenceDigest,
}
