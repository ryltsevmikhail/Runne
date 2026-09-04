use super::*;
use crate::protected_activation::enrollment_v3_tests::owned_and_sessions;

fn replace_binding(sessions: &Mutex<LocalSessionService>, field: usize) {
    let mut service = sessions.lock().unwrap();
    let old = service.current_binding();
    let ephemeral = old.ephemeral();
    let binding = RuntimeSessionBinding::new(
        runne_api::StableRuntimeBinding::new(
            if field == 5 {
                *uuid::Uuid::now_v7().as_bytes()
            } else {
                *old.stable().authority_id()
            },
            if field == 6 {
                runne_api::ApiPrincipalId::new("other-owner").unwrap()
            } else {
                old.stable().principal_id().clone()
            },
            if field == 7 {
                runne_api::EventLogLineageId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
            } else {
                *old.stable().lineage_id()
            },
            if field == 8 {
                "other-profile"
            } else {
                old.stable().profile_id()
            },
            if field == 9 {
                [99; 32]
            } else {
                *old.stable().schema_hash()
            },
            if field == 10 {
                [99; 32]
            } else {
                *old.stable().capability_digest()
            },
        )
        .unwrap(),
        if field == 0 {
            runne_api::DaemonInstanceId::from_bytes(*uuid::Uuid::now_v7().as_bytes())
        } else {
            ephemeral.daemon_instance_id()
        },
        ephemeral.launch_generation() + u64::from(field == 1),
        if field == 2 {
            *uuid::Uuid::now_v7().as_bytes()
        } else {
            *ephemeral.session_id()
        },
        ephemeral.authorization_epoch() + u64::from(field == 3),
        ephemeral.sensitivity_ceiling(),
        if field == 4 {
            [99; 32]
        } else {
            *old.certificate_sha256()
        },
    )
    .unwrap();
    *service = LocalSessionService::new_protected(
        binding,
        [16; 32],
        Duration::ZERO,
        Duration::from_secs(30),
    )
    .unwrap();
}

#[test]
fn live_enrollment_rejects_stale_owned_launch_before_admission() {
    for field in (0..3).chain(5..11) {
        let (owned, _, sessions) = owned_and_sessions();
        replace_binding(&sessions, field);
        assert!(
            LiveEnrollmentSession::capture(&sessions, &owned).is_err(),
            "field {field}"
        );
    }
}

#[test]
fn live_enrollment_rejects_rotation_without_running_store_action() {
    for field in 0..11 {
        let (owned, _, sessions) = owned_and_sessions();
        let live = LiveEnrollmentSession::capture(&sessions, &owned).unwrap();
        replace_binding(&sessions, field);
        let mut ran = false;
        let result = live.with_current(&sessions, || {
            ran = true;
            Ok(())
        });
        assert!(result.is_err(), "field {field}");
        assert!(!ran);
    }
}

#[test]
fn live_enrollment_keeps_rotation_locked_through_store_action() {
    let (owned, _, sessions) = owned_and_sessions();
    let live = LiveEnrollmentSession::capture(&sessions, &owned).unwrap();
    assert_eq!(
        live.with_current(&sessions, || {
            assert!(matches!(
                sessions.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            ));
            Ok(42)
        })
        .unwrap(),
        42
    );
    assert!(sessions.try_lock().is_ok());
}
