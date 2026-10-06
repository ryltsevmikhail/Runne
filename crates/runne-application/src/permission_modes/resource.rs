//! Permission actions and host-derived resource facts for preset V1.

/// Canonical effect taxonomy compiled by every permission preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PermissionAction {
    /// Read a file resource.
    FsRead,
    /// Create a new file at an absent target.
    FsCreate,
    /// Mutate an existing file.
    FsWrite,
    /// Remove a file or directory entry.
    FsDelete,
    /// Establish a network connection.
    NetworkConnect,
    /// Send data over an established network connection.
    NetworkSend,
    /// Start a process invocation with an immutable composite effect scope.
    ProcessStart,
}

/// Location relationship for a resolved resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceRelation {
    Inside,
    Outside,
    Unknown,
}

/// Frozen sensitivity classification of a resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    Nonsensitive,
    Sensitive,
    Unknown,
}

/// Whether the operation's maximum effect size is known and bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeBound {
    Bounded,
    Unbounded,
    Unknown,
}

/// Target existence established from held filesystem state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetState {
    Absent,
    Existing,
    Unknown,
}

/// Requested or observed filesystem object kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    RegularFile,
    Other,
    Unknown,
}

/// Whether target resolution used held, link-safe handles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionState {
    HeldSafe,
    AmbiguousOrUnheld,
}

/// Trusted facts required by the deterministic low-risk V1 rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceFacts {
    /// Workspace containment of the target.
    pub workspace: WorkspaceRelation,
    /// Frozen sensitive-path classifier result.
    pub sensitivity: Sensitivity,
    /// Maximum read or write size is known and bounded.
    pub size: SizeBound,
    /// Held descriptor/path resolution result.
    pub resolution: ResolutionState,
    /// Canonical held relative target path for bounded-root membership checks.
    pub resolved_path: Option<super::composite::FilesystemRoot>,
    /// File target existence.
    pub target: TargetState,
    /// Requested or observed file kind.
    pub object: ObjectKind,
    /// Requested file would be executable.
    pub executable: bool,
}

impl ResourceFacts {
    /// Unknown facts always remain ineligible for automatic admission.
    pub const fn unknown() -> Self {
        Self {
            workspace: WorkspaceRelation::Unknown,
            sensitivity: Sensitivity::Unknown,
            size: SizeBound::Unknown,
            resolution: ResolutionState::AmbiguousOrUnheld,
            resolved_path: None,
            target: TargetState::Unknown,
            object: ObjectKind::Unknown,
            executable: false,
        }
    }

    /// Host-verified fact set for a bounded nonsensitive workspace read.
    pub const fn safe_workspace_read() -> Self {
        Self {
            workspace: WorkspaceRelation::Inside,
            sensitivity: Sensitivity::Nonsensitive,
            size: SizeBound::Bounded,
            resolution: ResolutionState::HeldSafe,
            resolved_path: None,
            target: TargetState::Existing,
            object: ObjectKind::RegularFile,
            executable: false,
        }
    }

    /// Host-verified fact set for an atomic create-new regular file.
    pub const fn safe_workspace_create() -> Self {
        Self {
            workspace: WorkspaceRelation::Inside,
            sensitivity: Sensitivity::Nonsensitive,
            size: SizeBound::Bounded,
            resolution: ResolutionState::HeldSafe,
            resolved_path: None,
            target: TargetState::Absent,
            object: ObjectKind::RegularFile,
            executable: false,
        }
    }
}
