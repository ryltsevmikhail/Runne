impl NormalizedMutationCommand {
    /// Decodes and validates a versioned normalized command.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown version/tag, malformed field, trailing
    /// bytes, or an invalid transition.
    pub fn decode(value: &[u8]) -> Result<Self, SecurityStateError> {
        let mut input = value;
        if codec::byte(&mut input)? != VERSION {
            return Err(SecurityStateError::InvalidTransition);
        }
        let command = match codec::byte(&mut input)? {
            1 => Self::create_project(codec::id(&mut input)?, codec::display_name(&mut input)?)?,
            11 => Self::RenameProject {
                project_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
                display_name: codec::display_name(&mut input)?,
            },
            2 => Self::ArchiveProject {
                project_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            3 => Self::DeleteProject {
                project_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            4 => Self::CreateWorkspace {
                workspace_id: codec::id(&mut input)?,
                project_id: codec::id(&mut input)?,
                display_name: codec::display_name(&mut input)?,
            },
            5 => Self::bind_workspace_root(
                codec::id(&mut input)?,
                version(&mut input)?,
                codec::fixed(&mut input)?,
            )?,
            6 => Self::OpenWorkspace {
                workspace_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            7 => Self::CreateConversation {
                conversation_id: codec::id(&mut input)?,
                workspace_id: codec::id(&mut input)?,
            },
            8 => Self::GenerateText {
                conversation_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
                text: codec::message_text(&mut input)?,
            },
            9 => Self::CancelTaskRun {
                task_run_id: codec::id(&mut input)?,
                expected_version: version(&mut input)?,
            },
            12 => Self::SubmitTaskRun { conversation_id: codec::id(&mut input)?, workspace_id: codec::id(&mut input)? },
            10 => {
                let (
                    approval_id,
                    expected_version,
                    decision,
                    action_digest,
                    policy_revision,
                    renderer_generation,
                ) = approval::decode(&mut input)?;
                Self::ApprovalRespond {
                    approval_id,
                    expected_version,
                    decision,
                    action_digest,
                    policy_revision,
                    renderer_generation,
                }
            }
            _ => return Err(SecurityStateError::InvalidTransition),
        };
        command.encode()?;
        codec::finish(input)?;
        Ok(command)
    }
}
