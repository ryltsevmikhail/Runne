use gocode_api::{
    ApiPrincipalId, AuthoritativeCommandOutcome, CommandReconciliationContext,
    CommandReconciliationWitness, ProjectCommandAck,
};
use gocode_application::command_reconciliation::{
    CommandReconciliationEvidence, CommandReconciliationRepository,
    CommandReconciliationRepositoryError, CommandReconciliationService,
};
use gocode_domain::id::{CommandId, IdempotencyKey, ProjectId};

#[derive(Clone)]
struct Repository(CommandReconciliationEvidence);
impl CommandReconciliationRepository for Repository {
    fn reconcile_command(
        &self,
        _: &CommandReconciliationContext,
        _: &CommandReconciliationWitness,
    ) -> Result<CommandReconciliationEvidence, CommandReconciliationRepositoryError> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
struct FailingRepository(CommandReconciliationRepositoryError);
impl CommandReconciliationRepository for FailingRepository {
    fn reconcile_command(
        &self,
        _: &CommandReconciliationContext,
        _: &CommandReconciliationWitness,
    ) -> Result<CommandReconciliationEvidence, CommandReconciliationRepositoryError> {
        Err(self.0)
    }
}
fn context() -> CommandReconciliationContext {
    CommandReconciliationContext::new(
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d901"
            .parse::<CommandId>()
            .unwrap(),
        IdempotencyKey::new("key").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    )
}
fn witness() -> CommandReconciliationWitness {
    CommandReconciliationWitness::archive_project(
        "018f47a2-4f8c-7b52-8c35-7a3a14c2d902"
            .parse::<ProjectId>()
            .unwrap(),
        1,
    )
}

#[test]
fn service_maps_absence_and_started_evidence_without_an_outcome() {
    let absent =
        CommandReconciliationService::new(Repository(CommandReconciliationEvidence::NotCommitted))
            .reconcile_command(&context(), &witness())
            .unwrap();
    let started = CommandReconciliationService::new(Repository(
        CommandReconciliationEvidence::TextGenerationStarted,
    ))
    .reconcile_command(&context(), &witness())
    .unwrap();
    assert!(absent.is_not_committed_retryable());
    assert!(started.is_indeterminate());
}

#[test]
fn service_preserves_repository_failure_without_creating_an_outcome() {
    for error in [
        CommandReconciliationRepositoryError::Conflict,
        CommandReconciliationRepositoryError::Unavailable,
        CommandReconciliationRepositoryError::InvariantViolation,
    ] {
        assert_eq!(
            CommandReconciliationService::new(FailingRepository(error))
                .reconcile_command(&context(), &witness()),
            Err(error),
        );
    }
}

#[test]
fn service_maps_terminal_evidence_only_for_its_witness_operation() {
    let outcome = AuthoritativeCommandOutcome::project_archived(ProjectCommandAck {
        project_id: "018f47a2-4f8c-7b52-8c35-7a3a14c2d902"
            .parse::<ProjectId>()
            .unwrap(),
        new_version: 2,
    });
    let result = CommandReconciliationService::new(Repository(
        CommandReconciliationEvidence::Terminal(Box::new(outcome)),
    ))
    .reconcile_command(&context(), &witness())
    .unwrap();
    assert!(result.outcome().is_some());
}
