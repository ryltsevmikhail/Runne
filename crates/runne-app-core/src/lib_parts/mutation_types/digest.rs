impl MutationRequest {
    fn semantic_digest(&self) -> [u8; 32] {
        use sha2::Digest;
        let mut digest = sha2::Sha256::new();
        digest.update(b"gocode/app-core/mutation/v1\0");
        digest.update([
            operation_tag(self.operation),
            target_tag(self.target.kind()),
        ]);
        update_bytes(&mut digest, self.target.canonical_id().as_bytes());
        digest.update(self.expected_version.to_be_bytes());
        update_command_digest(&mut digest, &self.semantic_command);
        digest.finalize().into()
    }

    fn validate_invariants(&self) -> Result<(), AppCoreError> {
        let matches = command_matches(self);
        (matches && recovery_matches(self))
            .then_some(())
            .ok_or(AppCoreError::InvalidMutation)
    }
}

fn update_command_digest(
    digest: &mut sha2::Sha256,
    command: &CanonicalMutationCommand,
) {
    use sha2::Digest;
    match command {
            CanonicalMutationCommand::CreateProject {
                project_id,
                display_name,
            } => {
                digest.update([1]);
                update_id(digest, *project_id);
                update_bytes(digest, display_name.as_bytes());
            }
            CanonicalMutationCommand::RenameProject {
                project_id,
                display_name,
            } => {
                digest.update([11]);
                update_id(digest, *project_id);
                update_bytes(digest, display_name.as_bytes());
            }
            CanonicalMutationCommand::ArchiveProject { project_id } => {
                digest.update([2]);
                update_id(digest, *project_id);
            }
            CanonicalMutationCommand::DeleteProject { project_id } => {
                digest.update([3]);
                update_id(digest, *project_id);
            }
            CanonicalMutationCommand::CreateWorkspace {
                project_id,
                workspace_id,
                display_name,
            } => {
                digest.update([4]);
                update_id(digest, *project_id);
                update_id(digest, *workspace_id);
                update_bytes(digest, display_name.as_bytes());
            }
            CanonicalMutationCommand::BindWorkspaceRoot {
                workspace_id,
                admission_digest,
            } => {
                digest.update([5]);
                update_id(digest, *workspace_id);
                digest.update(admission_digest);
            }
            CanonicalMutationCommand::OpenWorkspace { workspace_id } => {
                digest.update([6]);
                update_id(digest, *workspace_id);
            }
            CanonicalMutationCommand::CreateConversation {
                conversation_id,
                workspace_id,
            } => {
                digest.update([7]);
                update_id(digest, *conversation_id);
                update_id(digest, *workspace_id);
            }
            CanonicalMutationCommand::GenerateText {
                conversation_id,
                text,
            } => {
                digest.update([8]);
                update_id(digest, *conversation_id);
                update_bytes(digest, text.as_bytes());
            }
            CanonicalMutationCommand::CancelTaskRun { task_run_id } => {
                digest.update([9]);
                update_id(digest, *task_run_id);
            }
            CanonicalMutationCommand::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt,
            } => {
                digest.update([12]);
                update_id(digest, *conversation_id);
                update_id(digest, *workspace_id);
                if let Some(prompt) = prompt {
                    update_bytes(digest, prompt.as_bytes());
                }
            }
            CanonicalMutationCommand::ApprovalRespond {
                approval_id,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            } => {
                digest.update([10]);
                update_id(digest, *approval_id);
                digest.update([match decision {
                    runne_runtime_client::ApprovalDecisionDto::Approve => 1,
                    runne_runtime_client::ApprovalDecisionDto::Deny => 2,
                }]);
                digest.update(action_digest);
                digest.update(policy_revision.to_be_bytes());
                digest.update(renderer_generation.to_be_bytes());
            }
    }
}
