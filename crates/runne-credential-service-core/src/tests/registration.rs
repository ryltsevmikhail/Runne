use runne_provider::{
    CredentialOperationAction, CredentialServiceDisposition, CredentialServiceEndpointRole,
    CredentialServiceReply,
};

use super::super::{
    CredentialRegistrationOutcome, CredentialServiceCore, CredentialServiceIngressFailure,
};
use super::support::{EPOCH, binding, mutation_frames, register, replay_register, runtime_reply};

#[test]
fn registration_is_desktop_only_idempotent_and_conflicts_fail_closed() {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    let first = binding(2, 12, 14, 100);
    let (outcome, ack1) = register(
        &mut core,
        7,
        first.clone(),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    assert_eq!(outcome, CredentialRegistrationOutcome::Installed);
    let (outcome, ack2) = replay_register(
        &mut core,
        7,
        first.clone(),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    assert_eq!(outcome, CredentialRegistrationOutcome::Idempotent);
    assert_eq!(ack1, ack2);
    assert_eq!(
        replay_register(
            &mut core,
            8,
            first.clone(),
            CredentialServiceEndpointRole::Desktop
        )
        .unwrap_err(),
        CredentialServiceDisposition::Denied,
    );
    assert_eq!(
        register(
            &mut core,
            7,
            binding(2, 13, 14, 100),
            CredentialServiceEndpointRole::Desktop
        )
        .unwrap_err(),
        CredentialServiceDisposition::Denied,
    );
    assert_eq!(
        register(&mut core, 7, first, CredentialServiceEndpointRole::Runtime).unwrap_err(),
        CredentialServiceDisposition::Denied,
    );
}

#[test]
fn supersession_and_restart_invalidate_old_sessions_and_admissions() {
    let mut core = registered_core();
    let (arm, _, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    assert_eq!(
        register(
            &mut core,
            8,
            binding(3, 13, 15, 200),
            CredentialServiceEndpointRole::Desktop
        )
        .unwrap()
        .0,
        CredentialRegistrationOutcome::Superseded,
    );
    assert!(matches!(
        runtime_reply(&mut core, &arm, 7, 10, |_| panic!()),
        Err(CredentialServiceIngressFailure::Invalidate)
    ));
    let mut restarted = CredentialServiceCore::with_test_epoch([9; 16]).unwrap();
    assert!(matches!(
        runtime_reply(&mut restarted, &arm, 7, 10, |_| panic!()),
        Err(CredentialServiceIngressFailure::Invalidate)
    ));
}

#[test]
fn same_runtime_rejoin_requires_the_next_attempt_and_exact_session() {
    let mut core = registered_core();
    let current = binding(2, 12, 14, 100);
    let rejoin = runne_api::CredentialServiceRegistrationBinding::new(
        *current.service_epoch(),
        *current.protected_session_id(),
        current.daemon_authority_generation(),
        current.runtime_generation(),
        current.supervisor_generation(),
        current.installed_generation(),
        *current.installation_owner(),
        *current.release_binding(),
        [33; 16],
        3,
        100,
    )
    .unwrap();

    assert_eq!(
        register(
            &mut core,
            7,
            rejoin.clone(),
            CredentialServiceEndpointRole::Desktop
        )
        .unwrap()
        .0,
        CredentialRegistrationOutcome::Superseded
    );
    let skipped = runne_api::CredentialServiceRegistrationBinding::new(
        *rejoin.service_epoch(),
        *rejoin.protected_session_id(),
        rejoin.daemon_authority_generation(),
        rejoin.runtime_generation(),
        rejoin.supervisor_generation(),
        rejoin.installed_generation(),
        *rejoin.installation_owner(),
        *rejoin.release_binding(),
        [34; 16],
        5,
        100,
    )
    .unwrap();
    assert_eq!(
        register(
            &mut core,
            7,
            skipped,
            CredentialServiceEndpointRole::Desktop
        )
        .unwrap_err(),
        CredentialServiceDisposition::Denied
    );
}

#[test]
fn wrong_endpoint_mac_replay_and_expiry_do_not_advance_session() {
    let mut core = registered_core();
    let (valid, _, _) = mutation_frames(1, 1, 7, CredentialOperationAction::Pair);
    assert!(matches!(
        core.handle_runtime(
            CredentialServiceEndpointRole::Writer,
            &valid,
            10,
            |_| panic!()
        ),
        Err(CredentialServiceIngressFailure::Invalidate)
    ));
    let mut bad_mac = valid.clone();
    *bad_mac.last_mut().unwrap() ^= 1;
    assert!(matches!(
        runtime_reply(&mut core, &bad_mac, 7, 10, |_| panic!()),
        Err(CredentialServiceIngressFailure::Invalidate)
    ));
    assert!(matches!(
        runtime_reply(&mut core, &valid, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Armed)
    ));
    assert!(matches!(
        runtime_reply(&mut core, &valid, 7, 10, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
    let (expired, _, _) = mutation_frames(2, 2, 7, CredentialOperationAction::Pair);
    assert!(matches!(
        runtime_reply(&mut core, &expired, 7, 21, |_| panic!()),
        Ok(CredentialServiceReply::Rejected(
            CredentialServiceDisposition::Denied
        ))
    ));
}

fn registered_core() -> CredentialServiceCore {
    let mut core = CredentialServiceCore::with_test_epoch(EPOCH).unwrap();
    register(
        &mut core,
        7,
        binding(2, 12, 14, 100),
        CredentialServiceEndpointRole::Desktop,
    )
    .unwrap();
    core
}
