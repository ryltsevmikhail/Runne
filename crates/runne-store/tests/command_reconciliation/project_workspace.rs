use super::*;
use std::sync::Mutex;

use runne_api::{
    ApiActor, AuthoritativeCommandOutcome, BindWorkspaceRootCommand, ProjectCommandAck,
    ProjectCommandContext, RootAdmissionVerificationContext, WorkspaceCommandAck,
};
use runne_application::{
    ports::{
        CurrentRootAdmissionContext, ProjectWorkspaceRepository, RootAdmissionLease,
        RootAdmissionVerifier, RootAdmissionVerifierError,
    },
    project_workspace_service::ProjectWorkspaceService,
};

#[derive(Clone)]
struct Current(RootAdmissionVerificationContext);
impl CurrentRootAdmissionContext for Current {
    type Lease = Self;
    fn acquire_root_admission_lease(&self) -> Result<Self::Lease, RootAdmissionVerifierError> {
        Ok(self.clone())
    }
}
impl RootAdmissionLease for Current {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        Ok(self.0.clone())
    }
}
struct Verifier(Mutex<Option<runne_api::VerifiedRootAdmissionClaims>>);
impl RootAdmissionVerifier for Verifier {
    fn verify_root_admission(
        &self,
        _: runne_api::RootHandleAdmission,
    ) -> Result<runne_api::VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or(RootAdmissionVerifierError::Rejected)
    }
}

fn terminal(
    fixture: &Fixture,
    command: CommandId,
    witness: CommandReconciliationWitness,
) -> AuthoritativeCommandOutcome {
    match fixture
        .repository
        .reconcile_command(&context(command), &witness)
        .unwrap()
    {
        CommandReconciliationEvidence::Terminal(outcome) => *outcome,
        other => panic!("expected terminal receipt, got {other:?}"),
    }
}

#[test]
fn project_receipts_map_to_exact_acknowledgements() {
    let created = Fixture::new("reconcile-project-created");
    let create = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Project".into()).unwrap(),
    );
    created
        .repository
        .create_project(
            "owner",
            command(11),
            &IdempotencyKey::new("key").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    assert_eq!(
        terminal(&created, command(11), create),
        AuthoritativeCommandOutcome::project_created(ProjectCommandAck {
            project_id: project(),
            new_version: 1
        })
    );

    let archived = Fixture::new("reconcile-project-archived");
    archived
        .repository
        .create_project(
            "owner",
            command(12),
            &IdempotencyKey::new("seed").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    archived
        .repository
        .archive_project(
            "owner",
            command(13),
            &IdempotencyKey::new("key").unwrap(),
            project(),
            1,
        )
        .unwrap();
    assert_eq!(
        terminal(
            &archived,
            command(13),
            CommandReconciliationWitness::archive_project(project(), 1)
        ),
        AuthoritativeCommandOutcome::project_archived(ProjectCommandAck {
            project_id: project(),
            new_version: 2
        })
    );

    let deleted = Fixture::new("reconcile-project-deleted");
    deleted
        .repository
        .create_project(
            "owner",
            command(14),
            &IdempotencyKey::new("seed").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    deleted
        .repository
        .delete_project(
            "owner",
            command(15),
            &IdempotencyKey::new("key").unwrap(),
            project(),
            1,
        )
        .unwrap();
    assert_eq!(
        terminal(
            &deleted,
            command(15),
            CommandReconciliationWitness::delete_project(project(), 1)
        ),
        AuthoritativeCommandOutcome::project_deleted(ProjectCommandAck {
            project_id: project(),
            new_version: 2
        })
    );
}

#[test]
fn workspace_create_and_open_receipts_map_to_exact_acknowledgements() {
    let fixture = Fixture::new("reconcile-workspace");
    fixture
        .repository
        .create_project(
            "owner",
            command(16),
            &IdempotencyKey::new("project").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    fixture
        .repository
        .create_workspace(
            "owner",
            command(17),
            &IdempotencyKey::new("key").unwrap(),
            Workspace::create(
                workspace(),
                project(),
                ProjectWorkspaceDisplayName::new("Workspace".into()).unwrap(),
            ),
        )
        .unwrap();
    assert_eq!(
        terminal(
            &fixture,
            command(17),
            CommandReconciliationWitness::create_workspace(
                workspace(),
                project(),
                ProjectWorkspaceDisplayNameInput::new("Workspace".into()).unwrap()
            )
        ),
        AuthoritativeCommandOutcome::workspace_created(WorkspaceCommandAck {
            workspace_id: workspace(),
            new_version: 1
        })
    );
    fixture
        .repository
        .open_workspace(
            "owner",
            command(18),
            &IdempotencyKey::new("key").unwrap(),
            workspace(),
            1,
        )
        .unwrap();
    assert_eq!(
        terminal(
            &fixture,
            command(18),
            CommandReconciliationWitness::open_workspace(workspace(), 1)
        ),
        AuthoritativeCommandOutcome::workspace_opened(WorkspaceCommandAck {
            workspace_id: workspace(),
            new_version: 2
        })
    );
}

#[test]
fn workspace_root_binding_receipt_requires_exact_consumed_admission_digest() {
    let fixture = Fixture::new("reconcile-workspace-bind");
    fixture.project_workspace();
    let admission = RootAdmissionVerificationContext::new(
        RootAdmissionVerificationContext::authority_digest_for("authority"),
        [2; 16],
        1,
        RootAdmissionVerificationContext::principal_digest_for("owner"),
        3,
        1,
        100,
    )
    .unwrap();
    let claims =
        runne_api::test_support::claims(admission.clone(), workspace(), 1, [7; 16], 200, [8; 32]);
    let service = ProjectWorkspaceService::new(
        fixture.repository.clone(),
        Current(admission),
        Verifier(Mutex::new(Some(claims))),
    );
    service
        .bind_workspace_root(
            ProjectCommandContext {
                command_id: command(19),
                idempotency_key: IdempotencyKey::new("key").unwrap(),
                principal: ApiPrincipalId::new("owner").unwrap(),
                actor: ApiActor::new("test").unwrap(),
            },
            BindWorkspaceRootCommand {
                workspace_id: workspace(),
                expected_version: 1,
                root_admission: runne_api::test_support::admission(),
            },
        )
        .unwrap();
    let witness = CommandReconciliationWitness::bind_workspace_root(workspace(), 1, [8; 32]);
    assert_eq!(
        terminal(&fixture, command(19), witness),
        AuthoritativeCommandOutcome::workspace_root_bound(WorkspaceCommandAck {
            workspace_id: workspace(),
            new_version: 2
        })
    );
    assert_eq!(
        fixture.repository.reconcile_command(
            &context(command(19)),
            &CommandReconciliationWitness::bind_workspace_root(workspace(), 1, [9; 32])
        ),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
}
