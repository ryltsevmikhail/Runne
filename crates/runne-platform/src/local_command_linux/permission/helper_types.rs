use runne_application::permission_modes::FilesystemPermission;

/// Filesystem operation represented by a strict tool-helper request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PermissionHelperOperationV1 {
    /// Reads one regular file whose metadata version is pinned in the request.
    Read,
    /// Creates one absent file using the bounded content carried by the request.
    CreateNew,
    /// Lists a pinned directory beneath the admitted root.
    List,
    /// Searches bounded regular files beneath a pinned directory.
    Search,
    /// Replaces a pinned regular file after its digest precondition.
    Replace,
    /// Runs an approved argv in a pinned directory with inherited containment.
    Command,
}

impl PermissionHelperOperationV1 {
    pub(super) const fn is_directory(self) -> bool {
        matches!(self, Self::List | Self::Search | Self::Command)
    }
    pub(in crate::local_command_linux) const fn scope_operation(self) -> Self {
        match self {
            Self::List | Self::Search => Self::Read,
            other => other,
        }
    }
    /// Returns the exact filesystem permissions required by this operation.
    pub const fn permissions(self) -> &'static [FilesystemPermission] {
        const READ: &[FilesystemPermission] = &[FilesystemPermission::Read];
        const CREATE: &[FilesystemPermission] = &[
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
        ];
        match self {
            Self::Read | Self::List | Self::Search => READ,
            Self::CreateNew => CREATE,
            Self::Command => &[
                FilesystemPermission::Read,
                FilesystemPermission::Create,
                FilesystemPermission::Write,
                FilesystemPermission::Delete,
            ],
            Self::Replace => &[FilesystemPermission::Read, FilesystemPermission::Write],
        }
    }
}

/// Filesystem metadata version expected for a Read target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionHelperTargetVersionV1 {
    /// Device number containing the target.
    pub device: u64,
    /// Inode number identifying the target.
    pub inode: u64,
    /// Target size in bytes.
    pub size: u64,
    /// Modification time seconds reported by the filesystem.
    pub mtime_sec: i64,
    /// Modification time nanosecond component.
    pub mtime_nsec: i64,
    /// Change time seconds reported by the filesystem.
    pub ctime_sec: i64,
    /// Change time nanosecond component.
    pub ctime_nsec: i64,
}

/// Read-only facts parsed from the exact helper request retained for execution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionHelperObservationV1 {
    pub(super) operation: PermissionHelperOperationV1,
    pub(super) path: String,
    pub(super) request_digest: [u8; 32],
    pub(super) arguments_digest: [u8; 32],
    pub(super) binding: PermissionHelperBindingObservationV1,
    pub(super) content_length: usize,
    pub(super) content_digest: [u8; 32],
    pub(super) root_device: u64,
    pub(super) root_inode: u64,
    pub(super) target: Option<PermissionHelperTargetVersionV1>,
    pub(super) expires_at_unix_ms: u64,
}

impl PermissionHelperObservationV1 {
    /// Returns the filesystem operation encoded in the request.
    pub const fn operation(&self) -> PermissionHelperOperationV1 {
        self.operation
    }

    /// Returns the relative target path parsed from the request.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Returns the digest of the exact encoded request bytes.
    pub const fn request_digest(&self) -> &[u8; 32] {
        &self.request_digest
    }

    /// Returns the decoded content length for CreateNew, or zero for Read.
    pub const fn content_length(&self) -> usize {
        self.content_length
    }

    /// Returns the digest of the decoded CreateNew content.
    pub const fn content_digest(&self) -> &[u8; 32] {
        &self.content_digest
    }

    /// Returns the canonical digest of the tool arguments parsed from the request.
    pub const fn arguments_digest(&self) -> &[u8; 32] {
        &self.arguments_digest
    }

    /// Returns the invocation and approval binding facts parsed from the request.
    pub fn binding(&self) -> &PermissionHelperBindingObservationV1 {
        &self.binding
    }

    /// Returns the workspace root device and inode captured in the request.
    pub const fn root_identity(&self) -> (u64, u64) {
        (self.root_device, self.root_inode)
    }

    /// Returns the pinned target version for Read, or `None` for CreateNew.
    pub const fn target_version(&self) -> Option<PermissionHelperTargetVersionV1> {
        self.target
    }
}

/// Read-only invocation facts parsed from the exact helper request bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PermissionHelperBindingObservationV1 {
    /// Task run identifier bound to the invocation.
    pub taskrun_id: String,
    /// Attempt identifier bound to the invocation.
    pub attempt_id: String,
    /// Cycle identifier bound to the invocation.
    pub cycle_id: String,
    /// Proposal index selected for execution.
    pub proposal_index: u32,
    /// Task run version observed when the proposal was created.
    pub taskrun_version: u64,
    /// Assignment fence observed when the proposal was created.
    pub assignment_fence: u64,
    /// Digest of the bound tool invocation.
    pub invocation_digest: String,
    /// Digest of the bound execution environment.
    pub environment_digest: String,
    /// Digest of the approval associated with the invocation.
    pub approval_digest: String,
    /// Unix time in milliseconds after which the request is expired.
    pub expires_at_unix_ms: u64,
}
