use super::{
    ApprovalDecisionDto, CanonicalId, CommandIdentity, CommandReconciliationRequest,
    CommandReconciliationWitness, RuntimeApiError, RuntimeApiErrorKind, invalid_request,
    reconciliation_display_name, validate_message_text, version,
};

impl CommandReconciliationRequest {
    /// Builds a validated create-project reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the display name is invalid.
    pub fn create_project(
        identity: CommandIdentity,
        project_id: CanonicalId,
        name: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::CreateProject {
                project_id,
                display_name: reconciliation_display_name(name.into())?,
            },
        })
    }
    /// Builds an archive-project witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the expected version is zero.
    pub fn archive_project(
        identity: CommandIdentity,
        project_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::ArchiveProject {
                project_id,
                expected_version: version(expected_version)?,
            },
        })
    }
    /// Builds a delete-project witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the expected version is zero.
    pub fn delete_project(
        identity: CommandIdentity,
        project_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::DeleteProject {
                project_id,
                expected_version: version(expected_version)?,
            },
        })
    }
    /// Builds a validated project-rename reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a zero version or invalid display name.
    pub fn rename_project(
        identity: CommandIdentity,
        project_id: CanonicalId,
        expected_version: u64,
        name: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::RenameProject {
                project_id,
                expected_version: version(expected_version)?,
                display_name: reconciliation_display_name(name.into())?,
            },
        })
    }
    /// Builds a validated create-workspace reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the display name is invalid.
    pub fn create_workspace(
        identity: CommandIdentity,
        workspace_id: CanonicalId,
        project_id: CanonicalId,
        name: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::CreateWorkspace {
                workspace_id,
                project_id,
                display_name: reconciliation_display_name(name.into())?,
            },
        })
    }
    /// Builds a root-binding witness without carrying root authority.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a zero version or non-canonical digest.
    pub fn bind_workspace_root(
        identity: CommandIdentity,
        workspace_id: CanonicalId,
        expected_version: u64,
        admission_digest: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let admission_digest = admission_digest.into();
        if admission_digest.len() != 64
            || !admission_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(invalid_request());
        }
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::BindWorkspaceRoot {
                workspace_id,
                expected_version: version(expected_version)?,
                admission_digest,
            },
        })
    }
    /// Builds an open-workspace witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the expected version is zero.
    pub fn open_workspace(
        identity: CommandIdentity,
        workspace_id: CanonicalId,
        expected_version: u64,
    ) -> Result<Self, RuntimeApiError> {
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::OpenWorkspace {
                workspace_id,
                expected_version: version(expected_version)?,
            },
        })
    }
    #[must_use]
    pub const fn create_conversation(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    ) -> Self {
        Self {
            identity,
            witness: CommandReconciliationWitness::CreateConversation {
                conversation_id,
                workspace_id,
            },
        }
    }

    #[must_use]
    pub const fn create_text_only_conversation(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    ) -> Self {
        Self {
            identity,
            witness: CommandReconciliationWitness::CreateTextOnlyConversation {
                conversation_id,
                workspace_id,
            },
        }
    }
    /// Builds a validated text-generation reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` for a zero version or invalid message text.
    pub fn generate_conversation_text(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        expected_version: u64,
        text: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let text = text.into();
        validate_message_text(&text)?;
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::GenerateConversationText {
                conversation_id,
                expected_version: version(expected_version)?,
                text,
            },
        })
    }
    #[must_use]
    pub const fn cancel_task_run(
        identity: CommandIdentity,
        task_run_id: CanonicalId,
        expected_version: u64,
    ) -> Self {
        Self {
            identity,
            witness: CommandReconciliationWitness::CancelTaskRun {
                task_run_id,
                expected_version,
            },
        }
    }
    #[must_use]
    pub const fn supersede_unknown_task_run(
        identity: CommandIdentity,
        predecessor_task_run_id: CanonicalId,
        expected_version: u64,
    ) -> Self {
        Self {
            identity,
            witness: CommandReconciliationWitness::SupersedeUnknownTaskRun {
                predecessor_task_run_id,
                expected_version,
            },
        }
    }
    /// Builds an atomic-submit reconciliation witness. The runtime owns the
    /// resulting `TaskRun` identity; the witness pins only the referenced
    /// aggregate roots of the submitted command.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when the prompt is invalid.
    pub fn submit_task_run(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
        prompt: impl Into<String>,
    ) -> Result<Self, RuntimeApiError> {
        let prompt = prompt.into();
        runne_api::TaskRunInput::new(prompt.clone())
            .map_err(|_| RuntimeApiError::new(RuntimeApiErrorKind::InvalidRequest))?;
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt: Some(prompt),
                model: None,
                profile: None,
                local_command: None,
            },
        })
    }

    /// Builds a promptless witness for reconciling a historical submit
    /// receipt written before `TaskRun` input became part of the command.
    #[must_use]
    pub const fn submit_task_run_legacy(
        identity: CommandIdentity,
        conversation_id: CanonicalId,
        workspace_id: CanonicalId,
    ) -> Self {
        Self {
            identity,
            witness: CommandReconciliationWitness::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt: None,
                model: None,
                profile: None,
                local_command: None,
            },
        }
    }

    /// Builds a policy-bound approval decision reconciliation witness.
    ///
    /// # Errors
    /// Returns `InvalidRequest` when a version is zero or the digest is empty.
    pub fn approval_decision(
        identity: CommandIdentity,
        approval_id: CanonicalId,
        expected_version: u64,
        decision: ApprovalDecisionDto,
        action_digest: [u8; 32],
        policy_revision: u64,
        renderer_generation: u64,
    ) -> Result<Self, RuntimeApiError> {
        if expected_version == 0
            || policy_revision == 0
            || renderer_generation == 0
            || action_digest == [0; 32]
        {
            return Err(invalid_request());
        }
        Ok(Self {
            identity,
            witness: CommandReconciliationWitness::ApprovalDecision {
                approval_id,
                expected_version,
                decision,
                action_digest: hex::encode(action_digest),
                policy_revision,
                renderer_generation,
            },
        })
    }
}
