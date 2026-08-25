use super::super::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair, CredentialFence,
    CredentialOperationAction as Action, CredentialOperationState as State,
    CredentialTransitionEvidence as Evidence, allows_structural_transition,
};

#[test]
fn credential_enrollment_transition_allows_only_the_closed_structural_graph() {
    let allowed = [
        (State::Prepared, State::Claimed),
        (State::Prepared, State::Failed),
        (State::Prepared, State::Expired),
        (State::Prepared, State::Cancelled),
        (State::Claimed, State::NativeEffectObserved),
        (State::Claimed, State::Failed),
        (State::NativeEffectObserved, State::ReadbackVerified),
        (State::NativeEffectObserved, State::Failed),
        (State::ReadbackVerified, State::Completed),
        (State::Completed, State::Tombstoned),
        (State::Failed, State::Tombstoned),
        (State::Expired, State::Tombstoned),
        (State::Cancelled, State::Tombstoned),
    ];
    for from in State::ALL {
        for to in State::ALL {
            assert_eq!(
                allows_structural_transition(from, to),
                allowed.contains(&(from, to)),
                "unexpected structural edge {from:?} -> {to:?}",
            );
        }
    }
    assert_eq!(Action::Pair as u8, 1);
}

#[test]
fn credential_enrollment_transition_requires_exact_post_claim_evidence() {
    let digest = measured(7);
    let fence = CredentialFence::new(3).unwrap();
    assert!(
        transition(
            Action::Pair,
            State::Claimed,
            State::Failed,
            Evidence::ExactAbsenceReadback(digest)
        )
        .is_ok()
    );
    assert!(transition(Action::Pair, State::Claimed, State::Failed, Evidence::None).is_err());
    assert!(
        transition(
            Action::Revoke,
            State::Claimed,
            State::Failed,
            Evidence::ExactAbsenceReadback(digest)
        )
        .is_err()
    );
    assert!(
        transition(
            Action::Revoke,
            State::Claimed,
            State::NativeEffectObserved,
            Evidence::RevokeFenceCommitted(fence)
        )
        .is_ok()
    );
    assert!(
        transition(
            Action::Pair,
            State::ReadbackVerified,
            State::Completed,
            Evidence::ExactVersionReadback(digest)
        )
        .is_ok()
    );
}

#[test]
fn credential_enrollment_review_version_actions_reject_absence_readback_and_completion() {
    let absence = Evidence::ExactAbsenceReadback(measured(40));
    for action in [
        Action::Pair,
        Action::MigrateLegacy,
        Action::WriterIdentityMigrationEffect,
        Action::WriterIdentityMigrationVerify,
    ] {
        assert!(
            transition(
                action,
                State::NativeEffectObserved,
                State::ReadbackVerified,
                absence
            )
            .is_err(),
            "{action:?} accepted contradictory absence readback"
        );
        assert!(
            transition(action, State::ReadbackVerified, State::Completed, absence).is_err(),
            "{action:?} completed from contradictory absence readback"
        );
    }
}

#[test]
fn credential_enrollment_review_absence_actions_reject_version_readback_and_completion() {
    let version = Evidence::ExactVersionReadback(measured(41));
    for action in [
        Action::Revoke,
        Action::RetiredVersionCleanup,
        Action::LegacySourceCleanup,
    ] {
        assert!(
            transition(
                action,
                State::NativeEffectObserved,
                State::ReadbackVerified,
                version
            )
            .is_err(),
            "{action:?} accepted contradictory version readback"
        );
        assert!(
            transition(action, State::ReadbackVerified, State::Completed, version).is_err(),
            "{action:?} completed from contradictory version readback"
        );
    }
}

#[test]
fn credential_enrollment_review_writer_effect_cannot_authorize_terminal_success() {
    for evidence in [
        Evidence::ExactVersionReadback(measured(42)),
        Evidence::ExactAbsenceReadback(measured(43)),
    ] {
        assert!(
            transition(
                Action::WriterIdentityMigrationEffect,
                State::NativeEffectObserved,
                State::ReadbackVerified,
                evidence,
            )
            .is_err()
        );
    }
}

#[test]
fn credential_enrollment_transition_rejects_shortcuts_and_post_claim_closure() {
    for transition in [
        (State::Claimed, State::Completed),
        (State::Claimed, State::Expired),
        (State::Claimed, State::Cancelled),
        (State::NativeEffectObserved, State::Expired),
        (State::NativeEffectObserved, State::Cancelled),
        (State::Completed, State::Failed),
        (State::Tombstoned, State::Prepared),
    ] {
        assert!(!allows_structural_transition(transition.0, transition.1));
    }
}

fn measured(value: u8) -> CredentialBindingDigest {
    CredentialBindingDigest::from_measured([value; 32]).unwrap()
}

fn transition(
    action: Action,
    from: State,
    to: State,
    evidence: Evidence,
) -> Result<super::super::TransitionCommand, super::super::CredentialEnrollmentError> {
    let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
    store.issue_transition_command(action, from, to, evidence)
}
