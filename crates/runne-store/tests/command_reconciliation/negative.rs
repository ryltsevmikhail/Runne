use super::*;

#[test]
fn every_receipt_family_reports_exact_absence_without_writes() {
    let fixture = Fixture::new("reconcile-absent-families");
    let project = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Project".into()).unwrap(),
    );
    let conversation =
        CommandReconciliationWitness::create_conversation(conversation(), workspace());
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command(31)), &project),
        Ok(CommandReconciliationEvidence::NotCommitted)
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command(32)), &conversation),
        Ok(CommandReconciliationEvidence::NotCommitted)
    );
}

#[test]
fn changed_identity_witness_and_family_are_conflicts_without_outcomes() {
    let fixture = Fixture::new("reconcile-all-collisions");
    fixture
        .repository
        .create_project(
            "owner",
            command(33),
            &IdempotencyKey::new("key").unwrap(),
            Project::create(
                project(),
                ProjectWorkspaceDisplayName::new("Project".into()).unwrap(),
            ),
        )
        .unwrap();
    let original = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Project".into()).unwrap(),
    );
    let changed = CommandReconciliationWitness::create_project(
        project(),
        ProjectWorkspaceDisplayNameInput::new("Changed".into()).unwrap(),
    );
    let changed_key = CommandReconciliationContext::new(
        command(33),
        IdempotencyKey::new("other").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    );
    let changed_principal = CommandReconciliationContext::new(
        command(33),
        IdempotencyKey::new("key").unwrap(),
        ApiPrincipalId::new("other").unwrap(),
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&changed_key, &original),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&changed_principal, &original),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&context(command(33)), &changed),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
    assert_eq!(
        fixture.repository.reconcile_command(
            &context(command(33)),
            &CommandReconciliationWitness::create_conversation(conversation(), workspace())
        ),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
    let changed_command = CommandReconciliationContext::new(
        command(34),
        IdempotencyKey::new("key").unwrap(),
        ApiPrincipalId::new("owner").unwrap(),
    );
    assert_eq!(
        fixture
            .repository
            .reconcile_command(&changed_command, &original),
        Err(CommandReconciliationRepositoryError::Conflict)
    );
}
