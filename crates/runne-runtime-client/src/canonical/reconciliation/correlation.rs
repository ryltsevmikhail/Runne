#[path = "correlation/approval.rs"]
mod approval;
#[path = "correlation/conversation_task_run.rs"]
mod conversation_task_run;
#[path = "correlation/text.rs"]
mod correlation_text;
#[path = "correlation/project_workspace.rs"]
mod project_workspace;

use super::reconciliation_wire::OutcomeWire;
use super::{CommandReconciliationOutcome, CommandReconciliationWitness, RuntimeApiError};

pub(super) fn correlate(
    witness: &CommandReconciliationWitness,
    outcome: OutcomeWire,
) -> Result<CommandReconciliationOutcome, RuntimeApiError> {
    match witness {
        CommandReconciliationWitness::CreateProject { .. }
        | CommandReconciliationWitness::ArchiveProject { .. }
        | CommandReconciliationWitness::DeleteProject { .. }
        | CommandReconciliationWitness::RenameProject { .. } => {
            project_workspace::correlate_project(witness, outcome)
        }
        CommandReconciliationWitness::CreateWorkspace { .. }
        | CommandReconciliationWitness::BindWorkspaceRoot { .. }
        | CommandReconciliationWitness::OpenWorkspace { .. } => {
            project_workspace::correlate_workspace(witness, outcome)
        }
        CommandReconciliationWitness::CreateConversation { .. }
        | CommandReconciliationWitness::CreateTextOnlyConversation { .. } => {
            conversation_task_run::correlate_conversation(witness, outcome)
        }
        CommandReconciliationWitness::GenerateConversationText { .. } => {
            conversation_task_run::correlate_generation(witness, outcome)
        }
        CommandReconciliationWitness::CancelTaskRun { .. }
        | CommandReconciliationWitness::SubmitTaskRun { .. }
        | CommandReconciliationWitness::SupersedeUnknownTaskRun { .. } => {
            conversation_task_run::correlate_task_run(witness, outcome)
        }
        CommandReconciliationWitness::ApprovalDecision { .. } => {
            approval::correlate_approval(witness, outcome)
        }
    }
}
