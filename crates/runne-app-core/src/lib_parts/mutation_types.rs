/// `AppCore`'s closed mutation target is validated by the anchored ledger.
pub type MutationTarget = runne_local_store::StoredMutationTarget;

/// Canonical, normalized command values. DTO construction happens only after
/// the digest has been anchored by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMutationCommand {
    CreateProject { project_id: CanonicalId, display_name: String },
    ArchiveProject { project_id: CanonicalId },
    DeleteProject { project_id: CanonicalId },
    CreateWorkspace { project_id: CanonicalId, workspace_id: CanonicalId, display_name: String },
    BindWorkspaceRoot { workspace_id: CanonicalId, admission_digest: [u8; 32] },
    OpenWorkspace { workspace_id: CanonicalId },
    CreateConversation { conversation_id: CanonicalId, workspace_id: CanonicalId },
    GenerateText { conversation_id: CanonicalId, text: String },
}

/// Redacted recovery detail that is safe to persist and render.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SafeRecoverySummary {
    pub operation: runne_local_store::MutationOperation,
    pub target: MutationTarget,
}

/// A normalized mutation request. Its semantic digest and command identity are
/// AppCore-owned and cannot be supplied by renderer callers.
#[derive(Clone, Debug)]
pub struct MutationRequest {
    operation: runne_local_store::MutationOperation,
    target: MutationTarget,
    expected_version: u64,
    semantic_command: CanonicalMutationCommand,
    recovery_summary: SafeRecoverySummary,
    command_identity: CommandIdentity,
    idempotency_key: String,
}

impl MutationRequest {
    /// Creates an AppCore-owned normalized Conversation create request.
    ///
    /// The idempotency key and semantic digest remain private to `AppCore`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid command identity or target.
    pub fn create_conversation(
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    ) -> Result<Self, AppCoreError> {
        let command_id = CanonicalId::now_v7();
        let idempotency_key = command_id.to_string();
        let command_identity = CommandIdentity::new(command_id, idempotency_key.clone())
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let target = MutationTarget::try_new(
            runne_local_store::MutationOperation::ConversationCreate,
            runne_local_store::MutationTargetKind::Conversation,
            runne_local_store::BoundedCanonicalId::parse(conversation_id.to_string().as_bytes())
                .map_err(|_| AppCoreError::InvalidMutation)?,
        )
        .map_err(|_| AppCoreError::InvalidMutation)?;
        Ok(Self::for_conversation(
            runne_local_store::MutationOperation::ConversationCreate,
            target,
            0,
            CanonicalMutationCommand::CreateConversation { conversation_id, workspace_id },
            command_identity,
            idempotency_key,
        ))
    }

    /// Creates an AppCore-owned normalized Project create request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target or command identity.
    pub fn create_project(project_id: CanonicalId, display_name: String) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::ProjectCreate,
            runne_local_store::MutationTargetKind::Project,
            project_id,
            0,
            CanonicalMutationCommand::CreateProject { project_id, display_name },
        )
    }

    /// Creates an AppCore-owned normalized Project versioned request.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero version, invalid target, or command identity.
    pub fn archive_project(project_id: CanonicalId, expected_version: u64) -> Result<Self, AppCoreError> {
        Self::existing_project(runne_local_store::MutationOperation::ProjectArchive, project_id, expected_version, CanonicalMutationCommand::ArchiveProject { project_id })
    }

    /// Creates an AppCore-owned normalized destructive Project request.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero version, invalid target, or command identity.
    pub fn delete_project(project_id: CanonicalId, expected_version: u64) -> Result<Self, AppCoreError> {
        Self::existing_project(runne_local_store::MutationOperation::ProjectDelete, project_id, expected_version, CanonicalMutationCommand::DeleteProject { project_id })
    }

    /// Creates an AppCore-owned normalized Workspace create request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target or command identity.
    pub fn create_workspace(project_id: CanonicalId, workspace_id: CanonicalId, display_name: String) -> Result<Self, AppCoreError> {
        Self::new(runne_local_store::MutationOperation::WorkspaceCreate, runne_local_store::MutationTargetKind::Workspace, workspace_id, 0, CanonicalMutationCommand::CreateWorkspace { project_id, workspace_id, display_name })
    }

    /// Creates an AppCore-owned normalized Workspace open request.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero version, invalid target, or command identity.
    pub fn open_workspace(workspace_id: CanonicalId, expected_version: u64) -> Result<Self, AppCoreError> {
        Self::new(runne_local_store::MutationOperation::WorkspaceOpen, runne_local_store::MutationTargetKind::Workspace, workspace_id, expected_version, CanonicalMutationCommand::OpenWorkspace { workspace_id })
    }

    fn existing_project(
        operation: runne_local_store::MutationOperation,
        project_id: CanonicalId,
        expected_version: u64,
        command: CanonicalMutationCommand,
    ) -> Result<Self, AppCoreError> {
        Self::new(operation, runne_local_store::MutationTargetKind::Project, project_id, expected_version, command)
    }

    fn new(
        operation: runne_local_store::MutationOperation,
        kind: runne_local_store::MutationTargetKind,
        id: CanonicalId,
        expected_version: u64,
        semantic_command: CanonicalMutationCommand,
    ) -> Result<Self, AppCoreError> {
        if expected_version == 0 && !matches!(operation, runne_local_store::MutationOperation::ProjectCreate | runne_local_store::MutationOperation::WorkspaceCreate | runne_local_store::MutationOperation::ConversationCreate) {
            return Err(AppCoreError::InvalidMutation);
        }
        let command_id = CanonicalId::now_v7();
        let idempotency_key = command_id.to_string();
        let command_identity = CommandIdentity::new(command_id, idempotency_key.clone()).map_err(|_| AppCoreError::InvalidMutation)?;
        let target = MutationTarget::try_new(operation, kind, runne_local_store::BoundedCanonicalId::parse(id.to_string().as_bytes()).map_err(|_| AppCoreError::InvalidMutation)?).map_err(|_| AppCoreError::InvalidMutation)?;
        Ok(Self::for_conversation(operation, target, expected_version, semantic_command, command_identity, idempotency_key))
    }

    fn for_conversation(
        operation: runne_local_store::MutationOperation,
        target: MutationTarget,
        expected_version: u64,
        semantic_command: CanonicalMutationCommand,
        command_identity: CommandIdentity,
        idempotency_key: String,
    ) -> Self {
        Self {
            operation,
            recovery_summary: SafeRecoverySummary { operation, target: target.clone() },
            target,
            expected_version,
            semantic_command,
            command_identity,
            idempotency_key,
        }
    }

    fn semantic_digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        digest.update(b"gocode/app-core/mutation/v1\0");
        digest.update([operation_tag(self.operation), target_tag(self.target.kind())]);
        update_bytes(&mut digest, self.target.canonical_id().as_bytes());
        digest.update(self.expected_version.to_be_bytes());
        match &self.semantic_command {
            CanonicalMutationCommand::CreateProject { project_id, display_name } => {
                digest.update([1]); update_id(&mut digest, *project_id); update_bytes(&mut digest, display_name.as_bytes());
            }
            CanonicalMutationCommand::ArchiveProject { project_id } => { digest.update([2]); update_id(&mut digest, *project_id); }
            CanonicalMutationCommand::DeleteProject { project_id } => { digest.update([3]); update_id(&mut digest, *project_id); }
            CanonicalMutationCommand::CreateWorkspace { project_id, workspace_id, display_name } => {
                digest.update([4]); update_id(&mut digest, *project_id); update_id(&mut digest, *workspace_id); update_bytes(&mut digest, display_name.as_bytes());
            }
            CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, admission_digest } => { digest.update([5]); update_id(&mut digest, *workspace_id); digest.update(admission_digest); }
            CanonicalMutationCommand::OpenWorkspace { workspace_id } => { digest.update([6]); update_id(&mut digest, *workspace_id); }
            CanonicalMutationCommand::CreateConversation { conversation_id, workspace_id } => {
                digest.update([7]); update_id(&mut digest, *conversation_id); update_id(&mut digest, *workspace_id);
            }
            CanonicalMutationCommand::GenerateText { conversation_id, text } => {
                digest.update([8]); update_id(&mut digest, *conversation_id); update_bytes(&mut digest, text.as_bytes());
            }
        }
        digest.finalize().into()
    }

    fn validate_invariants(&self) -> Result<(), AppCoreError> {
        let matches = command_matches(self);
        (matches && recovery_matches(self))
            .then_some(())
            .ok_or(AppCoreError::InvalidMutation)
    }
}

/// Opaque prepared mutation. It is one-shot because anchored state carries the
/// command identity and the dispatching transition accepts it only once.
pub struct PreparedMutationLease {
    runtime_identity: replay::StableRuntimeIdentity,
    gate_epoch: u64,
    anchored_record: runne_local_store::MutationRecord,
    request: MutationRequest,
    finalized_root: Option<FinalizedRootAdmission>,
}

/// One-shot root binding frozen at preparation. It cannot be recreated from an
/// ordinary decoded claim and is never exposed outside the coordinator.
struct FinalizedRootAdmission {
    admission: runne_runtime_client::ProtectedRootAdmission,
    runtime_identity: replay::StableRuntimeIdentity,
    workspace_id: CanonicalId,
    expected_version: u64,
    admission_digest: [u8; 32],
}

/// Move-only neutral host handoff for the bind-then-open workspace mutation.
/// It intentionally carries no platform path, handle, renderer reference, or
/// transport token.
pub struct PreparedWorkspaceOpen {
    bind: PreparedMutationLease,
    open: PreparedMutationLease,
    possible_send: bool,
}

impl std::fmt::Debug for PreparedWorkspaceOpen {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PreparedWorkspaceOpen(<redacted>)")
    }
}

impl PreparedWorkspaceOpen {
    pub(crate) const fn parts_and_possible_send_mut(
        &mut self,
    ) -> (
        &mut PreparedMutationLease,
        &mut PreparedMutationLease,
        &mut bool,
    ) {
        (&mut self.bind, &mut self.open, &mut self.possible_send)
    }
}

impl std::fmt::Debug for PreparedMutationLease {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PreparedMutationLease(<redacted>)")
    }
}

/// Authenticated, redacted runtime binding for host-only consumers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationAdmissionBinding {
    pub runtime_identity_digest: [u8; 32],
    pub principal_digest: [u8; 32],
    pub gate_epoch: u64,
}

include!("mutation_types/invariants.rs");
