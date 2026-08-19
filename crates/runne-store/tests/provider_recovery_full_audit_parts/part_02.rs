#[test]
fn crash_after_issue_before_start_effect_keeps_dispatching_and_reservations() {
    let (database, request, _record) = setup("recovery-after-issue", 3);
    let claim = issue_winner(&database, &request);
    let reopened = database.execution();
    let (_credential, binding) = credential(&database);
    let connection = database.connection();

    assert_eq!(dispatch_state(&database, &claim), ProviderDispatchState::Dispatching);
    assert_eq!(active_reservation_count(&connection), 2);
    assert_eq!(effect_start_count(&connection), 0);
    drop(connection);

    let receipt = reopened.start_effect(&claim, &binding).unwrap();
    assert!(receipt.matches_claim(&claim));
    assert_eq!(effect_start_count(&database.connection()), 1);
}

#[test]
fn crash_after_start_effect_before_dispatch_keeps_effect_cas() {
    let (database, request, _record) = setup("recovery-after-effect-start", 4);
    let claim = issue_winner(&database, &request);
    let (_credential, binding) = credential(&database);
    database
        .execution()
        .start_effect(&claim, &binding)
        .unwrap();
    let reopened = database.execution();
    let connection = database.connection();

    assert_eq!(dispatch_state(&database, &claim), ProviderDispatchState::Dispatching);
    assert_eq!(effect_start_count(&connection), 1);
    drop(connection);

    assert_eq!(
        reopened.start_effect(&claim, &binding),
        Err(ProviderAdmissionError::AuthorityDenied)
    );
    assert_eq!(effect_start_count(&database.connection()), 1);
}
