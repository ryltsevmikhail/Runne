use runne_api::{
    ApprovalDecision, CanonicalMessageText, CommandReconciliationWitness,
    ProjectWorkspaceDisplayNameInput,
};
use runne_domain::id::{ApprovalId, ConversationId, ProjectId, TaskRunId, WorkspaceId};

#[path = "wire/body.rs"]
mod body;
#[path = "wire/local_command.rs"]
mod local_command;
pub(super) use body::ReconciliationBody;
use body::SelectedProfileWire;

impl ReconciliationBody {
    pub(super) fn witness(self) -> Option<CommandReconciliationWitness> {
        match self {
            Self::CreateProject {
                project_id,
                display_name,
            } => Some(CommandReconciliationWitness::create_project(
                project(&project_id)?,
                name(display_name)?,
            )),
            Self::ArchiveProject {
                project_id,
                expected_version,
            } => Some(CommandReconciliationWitness::archive_project(
                project(&project_id)?,
                version(expected_version)?,
            )),
            Self::DeleteProject {
                project_id,
                expected_version,
            } => Some(CommandReconciliationWitness::delete_project(
                project(&project_id)?,
                version(expected_version)?,
            )),
            Self::RenameProject {
                project_id,
                expected_version,
                display_name,
            } => Some(CommandReconciliationWitness::rename_project(
                project(&project_id)?,
                version(expected_version)?,
                name(display_name)?,
            )),
            Self::CreateWorkspace {
                workspace_id,
                project_id,
                display_name,
            } => Some(CommandReconciliationWitness::create_workspace(
                workspace(&workspace_id)?,
                project(&project_id)?,
                name(display_name)?,
            )),
            Self::BindWorkspaceRoot {
                workspace_id,
                expected_version,
                admission_digest,
            } => Some(CommandReconciliationWitness::bind_workspace_root(
                workspace(&workspace_id)?,
                version(expected_version)?,
                digest(&admission_digest)?,
            )),
            Self::OpenWorkspace {
                workspace_id,
                expected_version,
            } => Some(CommandReconciliationWitness::open_workspace(
                workspace(&workspace_id)?,
                version(expected_version)?,
            )),
            Self::CreateConversation {
                conversation_id,
                workspace_id,
            } => Some(CommandReconciliationWitness::create_conversation(
                conversation(&conversation_id)?,
                workspace(&workspace_id)?,
            )),
            Self::CreateTextOnlyConversation {
                conversation_id,
                workspace_id,
            } => Some(CommandReconciliationWitness::create_text_only_conversation(
                conversation(&conversation_id)?,
                workspace(&workspace_id)?,
            )),
            Self::GenerateConversationText {
                conversation_id,
                expected_version,
                text,
            } => Some(CommandReconciliationWitness::generate_conversation_text(
                conversation(&conversation_id)?,
                version(expected_version)?,
                CanonicalMessageText::new(text).ok()?,
            )),
            Self::SubmitTaskRun {
                conversation_id,
                workspace_id,
                prompt,
                model,
                profile,
                local_command,
            } => {
                let conversation_id = conversation(&conversation_id)?;
                let workspace_id = workspace(&workspace_id)?;
                let selected = match profile {
                    Some(wire) => Some(decode_profile(wire)?),
                    None => None,
                };
                if let Some(command) = local_command {
                    if model.is_some() || selected.is_some() {
                        return None;
                    }
                    let command = command.into_domain()?;
                    let prompt = prompt?;
                    return Some(CommandReconciliationWitness::submit_task_run(
                        conversation_id,
                        workspace_id,
                        runne_domain::task_run::TaskRunInput::new(prompt)
                            .ok()?
                            .with_local_command(command)
                            .ok()?,
                    ));
                }
                match (prompt, model, selected) {
                    (Some(prompt), Some(model), selected) => {
                        Some(CommandReconciliationWitness::submit_task_run(
                            conversation_id,
                            workspace_id,
                            runne_domain::task_run::TaskRunInput::new(prompt)
                                .ok()?
                                .with_requested_model(model)
                                .ok()?
                                .pipe_selected(selected)?,
                        ))
                    }
                    (Some(prompt), None, selected) => {
                        Some(CommandReconciliationWitness::submit_task_run(
                            conversation_id,
                            workspace_id,
                            runne_domain::task_run::TaskRunInput::new(prompt)
                                .ok()?
                                .pipe_selected(selected)?,
                        ))
                    }
                    (None, Some(_), _) | (None, None, Some(_)) => None,
                    (None, None, None) => {
                        Some(CommandReconciliationWitness::submit_task_run_legacy(
                            conversation_id,
                            workspace_id,
                        ))
                    }
                }
            }
            Self::ApprovalDecision {
                approval_id,
                expected_version,
                decision,
                action_digest,
                policy_revision,
                renderer_generation,
            } => Some(CommandReconciliationWitness::approval_decision(
                approval(&approval_id)?,
                version(expected_version)?,
                match decision.as_str() {
                    "approve" => ApprovalDecision::Approve,
                    "deny" => ApprovalDecision::Deny,
                    _ => return None,
                },
                digest(&action_digest)?,
                version(policy_revision)?,
                version(renderer_generation)?,
            )),
            Self::SupersedeUnknownTaskRun {
                predecessor_task_run_id,
                expected_version,
            } => Some(CommandReconciliationWitness::supersede_unknown_task_run(
                taskrun(&predecessor_task_run_id)?,
                version(expected_version)?,
            )),
        }
    }
}

fn decode_profile(
    wire: SelectedProfileWire,
) -> Option<runne_domain::task_run::SelectedProviderProfile> {
    let raw = wire.profile_digest.as_bytes();
    if raw.len() != 64 || !raw.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(
            std::str::from_utf8(&raw[index * 2..index * 2 + 2]).ok()?,
            16,
        )
        .ok()?;
    }
    runne_domain::task_run::SelectedProviderProfile::new(wire.profile_id, digest).ok()
}

trait WithSelectedProfile {
    fn pipe_selected(
        self,
        selected: Option<runne_domain::task_run::SelectedProviderProfile>,
    ) -> Option<Self>
    where
        Self: Sized;
}
impl WithSelectedProfile for runne_domain::task_run::TaskRunInput {
    fn pipe_selected(
        self,
        selected: Option<runne_domain::task_run::SelectedProviderProfile>,
    ) -> Option<Self> {
        Some(if let Some(profile) = selected {
            self.with_selected_profile(profile).ok()?
        } else {
            self
        })
    }
}
fn project(value: &str) -> Option<ProjectId> {
    value.parse().ok()
}
fn workspace(value: &str) -> Option<WorkspaceId> {
    value.parse().ok()
}
fn conversation(value: &str) -> Option<ConversationId> {
    value.parse().ok()
}
fn taskrun(value: &str) -> Option<TaskRunId> {
    value.parse().ok()
}
fn approval(value: &str) -> Option<ApprovalId> {
    value.parse().ok()
}
fn version(value: u64) -> Option<u64> {
    (value != 0).then_some(value)
}
fn name(value: String) -> Option<ProjectWorkspaceDisplayNameInput> {
    ProjectWorkspaceDisplayNameInput::new(value).ok()
}
fn digest(value: &str) -> Option<[u8; 32]> {
    (value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| hex::decode(value).ok()?.try_into().ok())?
}
