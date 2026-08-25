/// `AppCore`'s closed mutation target is validated by the anchored ledger.
pub type MutationTarget = runne_local_store::StoredMutationTarget;

/// Canonical, normalized command values. DTO construction happens only after
/// the digest has been anchored by the coordinator.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CanonicalMutationCommand {
    CreateProject {
        project_id: CanonicalId,
        display_name: String,
    },
    ArchiveProject {
        project_id: CanonicalId,
    },
    DeleteProject {
        project_id: CanonicalId,
    },
    CreateWorkspace {
        project_id: CanonicalId,
        workspace_id: CanonicalId,
        display_name: String,
    },
    BindWorkspaceRoot {
        workspace_id: CanonicalId,
        admission_digest: [u8; 32],
    },
    OpenWorkspace {
        workspace_id: CanonicalId,
    },
    CreateConversation {
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    },
    GenerateText {
        conversation_id: CanonicalId,
        text: String,
    },
    CancelTaskRun {
        task_run_id: CanonicalId,
    },
    ApprovalRespond { approval_id: CanonicalId, decision: runne_runtime_client::ApprovalDecisionDto, action_digest: [u8; 32], policy_revision: u64, renderer_generation: u64 },
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
            CanonicalMutationCommand::CreateConversation {
                conversation_id,
                workspace_id,
            },
            command_identity,
            idempotency_key,
        ))
    }

    /// Creates an AppCore-owned normalized Project create request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target or command identity.
    pub fn create_project(
        project_id: CanonicalId,
        display_name: String,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::ProjectCreate,
            runne_local_store::MutationTargetKind::Project,
            project_id,
            0,
            CanonicalMutationCommand::CreateProject {
                project_id,
                display_name,
            },
        )
    }

    /// Creates an AppCore-owned normalized Project versioned request.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero version, invalid target, or command identity.
    pub fn archive_project(
        project_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, AppCoreError> {
        Self::existing_project(
            runne_local_store::MutationOperation::ProjectArchive,
            project_id,
            expected_version,
            CanonicalMutationCommand::ArchiveProject { project_id },
        )
    }

    /// Creates an AppCore-owned normalized destructive Project request.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero version, invalid target, or command identity.
    pub fn delete_project(
        project_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, AppCoreError> {
        Self::existing_project(
            runne_local_store::MutationOperation::ProjectDelete,
            project_id,
            expected_version,
            CanonicalMutationCommand::DeleteProject { project_id },
        )
    }

    /// Creates an AppCore-owned normalized Workspace create request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target or command identity.
    pub fn create_workspace(
        project_id: CanonicalId,
        workspace_id: CanonicalId,
        display_name: String,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::WorkspaceCreate,
            runne_local_store::MutationTargetKind::Workspace,
            workspace_id,
            0,
            CanonicalMutationCommand::CreateWorkspace {
                project_id,
                workspace_id,
                display_name,
            },
        )
    }

    /// Creates an AppCore-owned normalized Workspace open request.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero version, invalid target, or command identity.
    pub fn open_workspace(
        workspace_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::WorkspaceOpen,
            runne_local_store::MutationTargetKind::Workspace,
            workspace_id,
            expected_version,
            CanonicalMutationCommand::OpenWorkspace { workspace_id },
        )
    }

    /// Creates an AppCore-owned normalized `TaskRun` cancellation request.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid target, zero expected version, or
    /// command identity.
    pub fn cancel_task_run(
        task_run_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            runne_local_store::MutationOperation::TaskRunCancel,
            runne_local_store::MutationTargetKind::TaskRun,
            task_run_id,
            expected_version,
            CanonicalMutationCommand::CancelTaskRun { task_run_id },
        )
    }

    fn existing_project(
        operation: runne_local_store::MutationOperation,
        project_id: CanonicalId,
        expected_version: u64,
        command: CanonicalMutationCommand,
    ) -> Result<Self, AppCoreError> {
        Self::new(
            operation,
            runne_local_store::MutationTargetKind::Project,
            project_id,
            expected_version,
            command,
        )
    }

    fn new(
        operation: runne_local_store::MutationOperation,
        kind: runne_local_store::MutationTargetKind,
        id: CanonicalId,
        expected_version: u64,
        semantic_command: CanonicalMutationCommand,
    ) -> Result<Self, AppCoreError> {
        if expected_version == 0
            && !matches!(
                operation,
                runne_local_store::MutationOperation::ProjectCreate
                    | runne_local_store::MutationOperation::WorkspaceCreate
                    | runne_local_store::MutationOperation::ConversationCreate
            )
        {
            return Err(AppCoreError::InvalidMutation);
        }
        let command_id = CanonicalId::now_v7();
        let idempotency_key = command_id.to_string();
        let command_identity = CommandIdentity::new(command_id, idempotency_key.clone())
            .map_err(|_| AppCoreError::InvalidMutation)?;
        let target = MutationTarget::try_new(
            operation,
            kind,
            runne_local_store::BoundedCanonicalId::parse(id.to_string().as_bytes())
                .map_err(|_| AppCoreError::InvalidMutation)?,
        )
        .map_err(|_| AppCoreError::InvalidMutation)?;
        Ok(Self::for_conversation(
            operation,
            target,
            expected_version,
            semantic_command,
            command_identity,
            idempotency_key,
        ))
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
            recovery_summary: SafeRecoverySummary {
                operation,
                target: target.clone(),
            },
            target,
            expected_version,
            semantic_command,
            command_identity,
            idempotency_key,
        }
    }
}
include!("mutation_types/digest.rs");
include!("mutation_types/prepared.rs");
include!("mutation_types/invariants.rs");
include!("mutation_types/approval.rs");
