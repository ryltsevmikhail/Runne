fn update_id(digest: &mut sha2::Sha256, id: CanonicalId) {
    update_bytes(digest, id.to_string().as_bytes());
}

fn update_bytes(digest: &mut sha2::Sha256, value: &[u8]) {
    use sha2::Digest;
    digest.update(u32::try_from(value.len()).unwrap_or(u32::MAX).to_be_bytes());
    digest.update(value);
}

fn target_matches(target: &MutationTarget, id: CanonicalId) -> bool {
    target.canonical_id().as_bytes() == id.to_string().as_bytes()
}

fn recovery_matches(request: &MutationRequest) -> bool {
    request.recovery_summary.operation == request.operation
        && request.recovery_summary.target == request.target
}

fn command_matches(request: &MutationRequest) -> bool {
    use runne_local_store::MutationOperation as Operation;
    match (
        &request.operation,
        &request.target,
        &request.semantic_command,
    ) {
        (
            Operation::ProjectCreate,
            target,
            CanonicalMutationCommand::CreateProject { project_id, .. },
        ) => request.expected_version == 0 && target_matches(target, *project_id),
        (
            Operation::ProjectRename,
            target,
            CanonicalMutationCommand::RenameProject { project_id, .. },
        )
        | (
            Operation::ProjectArchive,
            target,
            CanonicalMutationCommand::ArchiveProject { project_id },
        )
        | (
            Operation::ProjectDelete,
            target,
            CanonicalMutationCommand::DeleteProject { project_id },
        ) => request.expected_version != 0 && target_matches(target, *project_id),
        (
            Operation::WorkspaceCreate,
            target,
            CanonicalMutationCommand::CreateWorkspace { workspace_id, .. },
        ) => request.expected_version == 0 && target_matches(target, *workspace_id),
        (
            Operation::WorkspaceBindRoot,
            target,
            CanonicalMutationCommand::BindWorkspaceRoot { workspace_id, .. },
        )
        | (
            Operation::WorkspaceOpen,
            target,
            CanonicalMutationCommand::OpenWorkspace { workspace_id },
        ) => request.expected_version != 0 && target_matches(target, *workspace_id),
        (
            Operation::ConversationCreate,
            target,
            CanonicalMutationCommand::CreateConversation {
                conversation_id, ..
            } | CanonicalMutationCommand::CreateTextOnlyConversation {
                conversation_id, ..
            },
        )
        | (
            Operation::TaskRunSubmit,
            target,
            CanonicalMutationCommand::SubmitTaskRun {
                conversation_id, ..
            },
        ) => request.expected_version == 0 && target_matches(target, *conversation_id),
        (
            Operation::ConversationGenerateText,
            target,
            CanonicalMutationCommand::GenerateText {
                conversation_id, ..
            },
        ) => request.expected_version != 0 && target_matches(target, *conversation_id),
        (
            Operation::TaskRunCancel,
            target,
            CanonicalMutationCommand::CancelTaskRun { task_run_id },
        ) => request.expected_version != 0 && target_matches(target, *task_run_id),
        (
            Operation::ApprovalRespond,
            target,
            CanonicalMutationCommand::ApprovalRespond {
                approval_id,
                action_digest,
                policy_revision,
                renderer_generation,
                ..
            },
        ) => {
            request.expected_version != 0
                && target_matches(target, *approval_id)
                && *action_digest != [0; 32]
                && *policy_revision != 0
                && *renderer_generation != 0
        }
        _ => false,
    }
}

const fn operation_tag(value: runne_local_store::MutationOperation) -> u8 {
    value as u8
}
const fn target_tag(value: runne_local_store::MutationTargetKind) -> u8 {
    value as u8
}
