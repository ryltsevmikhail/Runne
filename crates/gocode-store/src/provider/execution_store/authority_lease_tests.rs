use std::sync::Arc;

use gocode_application::provider::{ProviderAdmissionError, ProviderLeaseBindingKind};
use rusqlite::Connection;

use super::SqliteProviderExecutionStore;
use super::authority_test_support::{Fixture, authority_row, prepare_request};

#[test]
fn lease_is_valid_strictly_before_expiry_and_expired_at_or_after_boundary() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    fixture.clock.set(1_599);
    assert!(fixture.issue(1).is_ok());

    fixture.clock.set(1_600);
    assert_eq!(
        fixture.issue(2),
        Err(ProviderAdmissionError::CapabilityExpired)
    );
    fixture.clock.set(1_601);
    assert_eq!(
        fixture.issue(3),
        Err(ProviderAdmissionError::CapabilityExpired)
    );
    assert_eq!(fixture.store.admitted_count().unwrap(), 1);
}

#[test]
fn exact_renewal_extends_both_leases_by_600_and_preserves_utilization() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    assert!(fixture.issue(1).is_ok());
    let before = fixture.store.utilization().unwrap();

    fixture.clock.set(1_100);
    fixture
        .store
        .install_runtime_authority(&fixture.config)
        .unwrap();
    let state = authority_row(&fixture.path);
    assert_eq!(
        (state.capability_expires_at, state.approval_expires_at),
        (1_700, 1_700)
    );
    assert_eq!(fixture.store.utilization().unwrap(), before);

    fixture.clock.set(1_699);
    assert!(fixture.issue(2).is_ok());
    fixture.clock.set(1_700);
    assert_eq!(
        fixture.issue(3),
        Err(ProviderAdmissionError::CapabilityExpired)
    );
}

#[test]
fn immutable_lease_binding_changes_are_rejected_without_state_or_effect() {
    type Mutation = fn(&mut super::ProviderRuntimeAuthorityConfig);
    let cases: &[(&str, Mutation)] = &[
        ("runtime authority", |c| c.runtime_authority_id = [9; 16]),
        ("database generation", |c| c.database_generation += 1),
        ("principal", |c| c.principal_id = "other".into()),
        ("owner", |c| c.owner_id = "other".into()),
        ("scope", |c| c.scope = "other".into()),
        ("profile", |c| c.profile_digest = [9; 32]),
        ("pricing", |c| c.pricing_revision_digest = [9; 32]),
        ("activation kind", |c| {
            c.activation_binding_kind = ProviderLeaseBindingKind::ExternalOwnerPrivate
        }),
        ("activation digest", |c| {
            c.activation_binding_digest = [9; 32]
        }),
        ("token limit", |c| c.token_budget_limit += 1),
        ("cost limit", |c| c.cost_budget_limit_micros += 1),
    ];
    for (name, mutate) in cases {
        let fixture = Fixture::new(1_000);
        fixture.install();
        let before = authority_row(&fixture.path);
        let mut changed = fixture.config.clone();
        mutate(&mut changed);
        assert_eq!(
            fixture.store.install_runtime_authority(&changed),
            Err(ProviderAdmissionError::AuthorityConflict),
            "{name}"
        );
        assert_eq!(authority_row(&fixture.path), before, "{name}");
        assert_eq!(fixture.store.admitted_count().unwrap(), 0, "{name}");
    }
}

#[test]
fn generation_and_fence_mismatch_cannot_renew_or_write_effects() {
    for mutate in [
        |c: &mut super::ProviderRuntimeAuthorityConfig| c.generation += 1,
        |c: &mut super::ProviderRuntimeAuthorityConfig| c.fencing_token += 1,
    ] {
        let fixture = Fixture::new(1_000);
        fixture.install();
        let before = authority_row(&fixture.path);
        let mut changed = fixture.config.clone();
        mutate(&mut changed);
        assert_eq!(
            fixture.store.install_runtime_authority(&changed),
            Err(ProviderAdmissionError::StaleFencingToken)
        );
        assert_eq!(authority_row(&fixture.path), before);
        assert_eq!(fixture.store.admitted_count().unwrap(), 0);
    }
}

#[test]
fn stale_or_revoked_capability_and_approval_epochs_fail_typed_and_closed() {
    for capability in [true, false] {
        let fixture = Fixture::new(1_000);
        fixture.install();
        let mut revoked = fixture.config.clone();
        if capability {
            revoked.capability_revision += 1;
            revoked.capability_revocation_epoch += 1;
            revoked.capability_allowed = false;
        } else {
            revoked.approval_revision += 1;
            revoked.approval_revocation_epoch += 1;
            revoked.approval_allowed = false;
        }
        fixture.store.install_runtime_authority(&revoked).unwrap();
        let expected = if capability {
            ProviderAdmissionError::CapabilityRevoked
        } else {
            ProviderAdmissionError::ApprovalRevoked
        };
        assert_eq!(fixture.issue(1), Err(expected.clone()));
        assert_eq!(fixture.store.admitted_count().unwrap(), 0);

        let mut stale = revoked.clone();
        if capability {
            stale.capability_revocation_epoch -= 1;
        } else {
            stale.approval_revocation_epoch -= 1;
        }
        assert_eq!(
            fixture.store.install_runtime_authority(&stale),
            Err(expected.clone())
        );
        let mut stale_revision = revoked;
        if capability {
            stale_revision.capability_revision -= 1;
        } else {
            stale_revision.approval_revision -= 1;
        }
        assert_eq!(
            fixture.store.install_runtime_authority(&stale_revision),
            Err(expected)
        );
        assert_eq!(fixture.store.admitted_count().unwrap(), 0);
    }
}

#[test]
fn denial_disposition_requires_a_prior_allowed_state() {
    for capability in [true, false] {
        let fixture = Fixture::new(1_000);
        let mut denied = fixture.config.clone();
        if capability {
            denied.capability_allowed = false;
        } else {
            denied.approval_allowed = false;
        }
        fixture.store.install_runtime_authority(&denied).unwrap();
        fixture.store.install_runtime_authority(&denied).unwrap();
        let expected = if capability {
            ProviderAdmissionError::CapabilityDenied
        } else {
            ProviderAdmissionError::ApprovalDenied
        };
        assert_eq!(fixture.issue(1), Err(expected));
    }
}

#[test]
fn revocation_disposition_requires_a_prior_allowed_state() {
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
        fixture.store.install_runtime_authority(&revoked).unwrap();
        let expected = if capability {
            ProviderAdmissionError::CapabilityRevoked
        } else {
            ProviderAdmissionError::ApprovalRevoked
        };
        assert_eq!(fixture.issue(1), Err(expected));
    }
}

#[test]
fn revocation_transition_requires_new_revision_and_epoch() {
    for capability in [true, false] {
        let fixture = Fixture::new(1_000);
        fixture.install();
        let mut denied = fixture.config.clone();
        let expected = if capability {
            denied.capability_allowed = false;
            ProviderAdmissionError::CapabilityRevoked
        } else {
            denied.approval_allowed = false;
            ProviderAdmissionError::ApprovalRevoked
        };
        assert_eq!(
            fixture.store.install_runtime_authority(&denied),
            Err(expected)
        );
        assert!(fixture.issue(1).is_ok());
    }
}

#[test]
fn persisted_revocation_evidence_survives_reopen() {
    let fixture = Fixture::new(1_000);
    fixture.install();
    let mut revoked = fixture.config.clone();
    revoked.capability_allowed = false;
    revoked.capability_revision += 1;
    revoked.capability_revocation_epoch += 1;
    fixture.store.install_runtime_authority(&revoked).unwrap();
    let path = fixture.path.clone();
    let _directory = fixture.directory;
    drop(fixture.store);

    let reopened = SqliteProviderExecutionStore::open_with_now(&path, Arc::new(|| 1_100)).unwrap();
    assert_eq!(
        reopened.issue(&prepare_request(&path, 1)),
        Err(ProviderAdmissionError::CapabilityRevoked)
    );
    let markers: (i64, i64) = Connection::open(path)
        .unwrap()
        .query_row(
            "SELECT capability_revocation_observed, approval_revocation_observed
             FROM provider_runtime_authority_state WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(markers, (1, 0));
}
