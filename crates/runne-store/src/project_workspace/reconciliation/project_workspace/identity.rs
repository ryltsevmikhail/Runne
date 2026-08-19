use runne_api::{
    CommandReconciliationContext, CommandReconciliationWitness, CommandReconciliationWitnessRef,
};
use runne_application::command_reconciliation::CommandReconciliationRepositoryError as Error;

use super::super::super::fingerprint::{FingerprintInput, semantic_fingerprint};
use super::super::super::receipts::{Operation, ReceiptRequest, Scope};

pub(super) fn request<'a>(
    store: &'a crate::store::StoreTransaction,
    context: &'a CommandReconciliationContext,
    witness: &'a CommandReconciliationWitness,
) -> Result<ReceiptRequest<'a>, Error> {
    let authority = &store.runtime_authority_id().0;
    let principal = context.principal().as_str();
    let (scope, related, expected, name, digest) = match witness.view() {
        CommandReconciliationWitnessRef::CreateProject {
            project_id,
            display_name,
        } => (
            Scope::project(Operation::CreateProject, project_id.into_bytes()),
            None,
            None,
            Some(display_name.as_str()),
            None,
        ),
        CommandReconciliationWitnessRef::ArchiveProject {
            project_id,
            expected_version,
        } => (
            Scope::project(Operation::ArchiveProject, project_id.into_bytes()),
            None,
            Some(expected_version),
            None,
            None,
        ),
        CommandReconciliationWitnessRef::DeleteProject {
            project_id,
            expected_version,
        } => (
            Scope::project(Operation::DeleteProject, project_id.into_bytes()),
            None,
            Some(expected_version),
            None,
            None,
        ),
        CommandReconciliationWitnessRef::CreateWorkspace {
            workspace_id,
            project_id,
            display_name,
        } => (
            Scope::workspace(Operation::CreateWorkspace, workspace_id.into_bytes()),
            Some(project_id.into_bytes()),
            None,
            Some(display_name.as_str()),
            None,
        ),
        CommandReconciliationWitnessRef::BindWorkspaceRoot {
            workspace_id,
            expected_version,
            admission_digest,
        } => (
            Scope::workspace(Operation::BindWorkspaceRoot, workspace_id.into_bytes()),
            None,
            Some(expected_version),
            None,
            Some(admission_digest),
        ),
        CommandReconciliationWitnessRef::OpenWorkspace {
            workspace_id,
            expected_version,
        } => (
            Scope::workspace(Operation::OpenWorkspace, workspace_id.into_bytes()),
            None,
            Some(expected_version),
            None,
            None,
        ),
        _ => return Err(Error::InvariantViolation),
    };
    let fingerprint = semantic_fingerprint(FingerprintInput {
        authority,
        principal,
        command_id: context.command_id(),
        key: context.idempotency_key(),
        scope,
        related_id: related,
        expected_version: expected,
        display_name: name,
        admission_digest: digest.as_ref(),
    });
    Ok(ReceiptRequest {
        authority,
        principal,
        command_id: context.command_id(),
        key: context.idempotency_key(),
        scope,
        fingerprint,
    })
}
