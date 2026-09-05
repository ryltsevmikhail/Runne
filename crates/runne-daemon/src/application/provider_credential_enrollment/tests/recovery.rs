use runne_api::ProviderCredentialEnrollmentHostError;
use runne_provider::{CredentialOperationAction, CredentialOperationState};

use super::super::{CredentialEnrollmentRecoveryGateway, WriterExitDiagnostic};

pub(super) mod fixture;

use fixture::{FailurePoint, Fixture, StatefulReader};

#[test]
fn enrollment_recovery_revoke_completes_against_the_already_fenced_head() {
    let fixture = Fixture::new(CredentialOperationAction::Revoke, FailurePoint::None);
    let reader = StatefulReader::new(&fixture);
    let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);

    gateway.reconcile_online(100).unwrap();

    assert_eq!(fixture.state(), CredentialOperationState::Completed);
    assert_eq!(
        fixture.events(),
        ["reconcile", "mark", "readback", "bind", "complete"]
    );
    let receipt = fixture.receipt().unwrap();
    assert_eq!(receipt.action(), CredentialOperationAction::Revoke);
    assert_eq!(receipt.lifecycle_revision().get(), 2);
    assert_eq!(receipt.fence().get(), 2);
    assert_eq!(receipt.readiness_revision().get(), 2);
    assert!(receipt.active_version().is_none());
}

#[test]
fn enrollment_recovery_legacy_cleanup_accepts_newer_head_after_rotation() {
    let fixture = Fixture::legacy_cleanup_after_rotation();
    let reader = StatefulReader::new(&fixture);
    let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);
    gateway.reconcile_online(100).unwrap();
    // The verified legacy cleanup is tombstoned after its durable receipt.
    assert_eq!(fixture.state(), CredentialOperationState::Tombstoned);
    let receipt = fixture.receipt().unwrap();
    assert_eq!(receipt.predecessor_lifecycle_revision().get(), 2);
    assert_eq!(receipt.lifecycle_revision().get(), 3);
    assert_eq!(receipt.fence().get(), 3);
    assert_eq!(receipt.readiness_observation_id(), None);
}

#[test]
fn enrollment_recovery_retired_cleanup_completes_after_exact_absence() {
    let fixture = Fixture::retired_cleanup(FailurePoint::None);
    let reader = StatefulReader::new(&fixture);
    let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);

    gateway.reconcile_online(100).unwrap();

    assert_eq!(fixture.state(), CredentialOperationState::Completed);
    assert_eq!(
        fixture.events(),
        ["reconcile", "mark", "readback", "bind", "complete"]
    );
    let receipt = fixture.receipt().unwrap();
    assert_eq!(
        receipt.action(),
        CredentialOperationAction::RetiredVersionCleanup
    );
    assert_eq!(
        receipt.readback_disposition(),
        runne_provider::CredentialReadbackDisposition::ExactAbsence
    );
    assert_eq!(receipt.lifecycle_revision().get(), 2);
    assert_eq!(receipt.fence().get(), 2);
    assert_eq!(receipt.readiness_revision().get(), 2);
}

#[test]
fn enrollment_recovery_legacy_cleanup_preserves_v28_head_without_readiness_observation() {
    let fixture = Fixture::legacy_cleanup(FailurePoint::None);
    let reader = StatefulReader::new(&fixture);
    let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);

    gateway.reconcile_online(100).unwrap();

    // The verified legacy cleanup is tombstoned after its durable receipt.
    assert_eq!(fixture.state(), CredentialOperationState::Tombstoned);
    assert_eq!(
        fixture.events(),
        [
            "reconcile",
            "mark",
            "readback",
            "bind",
            "complete",
            "tombstone"
        ]
    );
    let receipt = fixture.receipt().unwrap();
    assert_eq!(
        receipt.action(),
        CredentialOperationAction::LegacySourceCleanup
    );
    assert_eq!(receipt.readiness_observation_id(), None);
    assert_eq!(receipt.lifecycle_revision().get(), 2);
    assert_eq!(receipt.fence().get(), 2);
    assert_eq!(receipt.readiness_revision().get(), 2);
}

#[test]
fn enrollment_recovery_writer_identity_actions_are_unsupported_without_durable_transition() {
    for action in [
        CredentialOperationAction::WriterIdentityMigrationEffect,
        CredentialOperationAction::WriterIdentityMigrationVerify,
    ] {
        let fixture = Fixture::writer_identity_migration(action);
        let reader = StatefulReader::new(&fixture);
        let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);

        assert_eq!(
            gateway.reconcile_online(100),
            Err(ProviderCredentialEnrollmentHostError::Unsupported)
        );
        assert_eq!(fixture.state(), CredentialOperationState::Claimed);
        assert_eq!(fixture.events(), ["reconcile"]);
        assert!(fixture.receipt().is_none());
    }
}

#[test]
fn enrollment_recovery_failures_stop_before_downstream_completion() {
    for (failure, state, events) in [
        (
            FailurePoint::Mark,
            CredentialOperationState::Claimed,
            &["reconcile", "mark"][..],
        ),
        (
            FailurePoint::Readback,
            CredentialOperationState::NativeEffectObserved,
            &["reconcile", "mark", "readback"][..],
        ),
        (
            FailurePoint::Bind,
            CredentialOperationState::NativeEffectObserved,
            &["reconcile", "mark", "readback", "bind"][..],
        ),
        (
            FailurePoint::Complete,
            CredentialOperationState::ReadbackVerified,
            &["reconcile", "mark", "readback", "bind", "complete"][..],
        ),
    ] {
        let fixture = Fixture::retired_cleanup(failure);
        let reader = StatefulReader::new(&fixture);
        let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);

        assert_eq!(
            gateway.reconcile_online(100),
            Err(ProviderCredentialEnrollmentHostError::Unavailable)
        );
        assert_eq!(fixture.state(), state);
        assert_eq!(fixture.events(), events);
        assert!(fixture.receipt().is_none());
    }
}

#[test]
fn writer_exit_is_diagnostic_only() {
    for diagnostic in [WriterExitDiagnostic::Exited, WriterExitDiagnostic::TimedOut] {
        let fixture = Fixture::retired_cleanup(FailurePoint::None);
        let reader = StatefulReader::new(&fixture);
        let gateway = CredentialEnrollmentRecoveryGateway::new(&fixture, &reader);

        gateway
            .reconcile_after_writer_exit(100, diagnostic)
            .unwrap();

        assert_eq!(fixture.state(), CredentialOperationState::Completed);
        assert_eq!(
            fixture.events(),
            ["reconcile", "mark", "readback", "bind", "complete"]
        );
    }
}
