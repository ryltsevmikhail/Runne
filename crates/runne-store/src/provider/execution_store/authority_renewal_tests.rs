use rusqlite::Connection;

use runne_application::provider::ProviderAdmissionError;

use super::authority_test_support::{Fixture, authority_row};

#[test]
fn current_launch_renews_after_two_idle_lease_windows_without_resetting_policy_state() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let before_revision = authority_row(&fixture.path).state_revision;
    let before_budget = fixture.store.utilization().unwrap();

    fixture.clock.set(1_601);
    assert!(
        fixture
            .store
            .renew_runtime_launch_lease(fixture.launch())
            .unwrap()
    );
    assert_eq!(authority_row(&fixture.path).capability_expires_at, 2_201);

    fixture.clock.set(2_202);
    assert!(
        fixture
            .store
            .renew_runtime_launch_lease(fixture.launch())
            .unwrap()
    );
    let after = authority_row(&fixture.path);
    assert_eq!(after.capability_expires_at, 2_802);
    assert_eq!(after.approval_expires_at, 2_802);
    assert_eq!(after.state_revision, before_revision);
    assert_eq!(fixture.store.utilization().unwrap(), before_budget);
    assert!(fixture.issue(1).is_ok());
}

#[test]
fn renewal_is_skipped_outside_bounded_window_and_permitted_inside_it() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    fixture.clock.set(1_479);
    let before = authority_row(&fixture.path);
    assert!(
        !fixture
            .store
            .renew_runtime_launch_lease(fixture.launch())
            .unwrap()
    );
    assert_eq!(authority_row(&fixture.path), before);

    fixture.clock.set(1_480);
    assert!(
        fixture
            .store
            .renew_runtime_launch_lease(fixture.launch())
            .unwrap()
    );
    assert_eq!(authority_row(&fixture.path).capability_expires_at, 2_080);
}

#[test]
fn unresolved_and_uncertain_attempts_block_expiry_extension_atomically() {
    for state in [1, 6] {
        let fixture = Fixture::new(1_000);
        fixture.install();
        fixture.issue(1).unwrap();
        if state == 6 {
            Connection::open(&fixture.path)
                .unwrap()
                .execute("UPDATE provider_dispatch_attempts SET state = 6", [])
                .unwrap();
        }
        fixture.clock.set(1_601);
        let before = authority_row(&fixture.path);
        let budget = fixture.store.utilization().unwrap();
        assert_eq!(
            fixture.store.renew_runtime_launch_lease(fixture.launch()),
            Err(ProviderAdmissionError::PostClaimUncertain)
        );
        assert_eq!(authority_row(&fixture.path), before);
        assert_eq!(fixture.store.utilization().unwrap(), budget);
    }
}

#[test]
fn settled_history_does_not_prevent_renewal() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    fixture.issue(1).unwrap();
    Connection::open(&fixture.path)
        .unwrap()
        .execute(
            "UPDATE provider_dispatch_attempts SET state = 5, settlement_digest = zeroblob(32)",
            [],
        )
        .unwrap();
    fixture.clock.set(1_601);
    assert!(
        fixture
            .store
            .renew_runtime_launch_lease(fixture.launch())
            .unwrap()
    );
}

#[test]
fn stale_and_revoked_launch_proofs_cannot_extend_authority() {
    let stale = Fixture::new(1_000);
    stale.install();
    stale.clock.set(1_601);
    let replacement = stale.activate(&stale.config);
    let after_activation = authority_row(&stale.path);
    assert_eq!(
        stale.store.renew_runtime_launch_lease(stale.launch()),
        Err(ProviderAdmissionError::StaleFencingToken)
    );
    assert_eq!(authority_row(&stale.path), after_activation);
    assert!(
        !stale
            .store
            .renew_runtime_launch_lease(&replacement)
            .unwrap()
    );

    for capability in [true, false] {
        let fixture = Fixture::new(1_000);
        fixture.install();
        let mut revoked = fixture.config.clone();
        if capability {
            revoked.capability_allowed = false;
            revoked.capability_revision += 1;
            revoked.capability_revocation_epoch += 1;
        } else {
            revoked.approval_allowed = false;
            revoked.approval_revision += 1;
            revoked.approval_revocation_epoch += 1;
        }
        fixture.activate(&revoked);
        fixture.clock.set(2_000);
        let before = authority_row(&fixture.path);
        let expected = if capability {
            ProviderAdmissionError::CapabilityRevoked
        } else {
            ProviderAdmissionError::ApprovalRevoked
        };
        assert_eq!(
            fixture.store.renew_runtime_launch_lease(fixture.launch()),
            Err(expected)
        );
        assert_eq!(authority_row(&fixture.path), before);
    }
}
