use super::*;

#[test]
fn discovery_returns_only_same_owner_prepared_cleanup_without_admission() {
    for case in [0, 1] {
        with_session(case, |mut session, _, control, operation, _| {
            let expected = if case == 0 {
                vec![operation.as_bytes()]
            } else {
                vec![]
            };
            assert_eq!(session.discover_cleanup().unwrap(), expected);
            assert_eq!(session.discover_cleanup().unwrap(), expected);
            assert!(!session.recovery.started);
            assert!(session.recovery.pending.is_none());
            assert!(session.recovery.ready.is_none());
            assert!(session.take_bound_broker_handoff().is_err());
            assert_eq!(
                control.store.load_operation(operation).unwrap().state(),
                runne_provider::CredentialOperationState::Prepared
            );
            control
                .store
                .cancel_before_claim(
                    runne_provider::ClosePreparedCredentialOperation::new(
                        operation,
                        runne_provider::CredentialOperationState::Cancelled,
                    )
                    .unwrap(),
                )
                .unwrap();
            assert!(session.discover_cleanup().unwrap().is_empty());
        });
    }
}
