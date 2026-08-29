use runne_provider::CredentialOperationAction;

use super::effect::{execute_non_pair_effect, execute_pair_effect};
use super::effect_test_support::{
    EffectCall, assert_frames, claimed, claimed_with_diagnostic_failure, pair_authorized,
    pair_authorized_with_diagnostic_failure,
};

#[test]
fn pair_effect_invokes_sealed_writer_and_observes_its_result() {
    for succeeds in [true, false] {
        let fixture = pair_authorized(succeeds);

        assert_eq!(execute_pair_effect(fixture.authority).is_ok(), succeeds);
        assert_eq!(*fixture.calls.lock().expect("calls"), vec![EffectCall::Create]);
        assert_frames(&fixture.written, true);
    }
}

#[test]
fn pair_diagnostic_failure_closes_after_native_writer_invocation() {
    let fixture = pair_authorized_with_diagnostic_failure();

    assert!(execute_pair_effect(fixture.authority).is_err());
    assert_eq!(*fixture.calls.lock().expect("calls"), vec![EffectCall::Create]);
    assert_frames(&fixture.written, false);
}

#[test]
fn writer_identity_migration_is_rejected_without_native_observation() {
    for action in [
        CredentialOperationAction::WriterIdentityMigrationEffect,
        CredentialOperationAction::WriterIdentityMigrationVerify,
    ] {
        let fixture = claimed(action);
        let authority = fixture
            .claimed
            .authorize_without_secret()
            .expect("non-pair authority");

        assert!(execute_non_pair_effect(authority).is_err());
        assert!(fixture.calls.lock().expect("calls").is_empty());
        assert_frames(&fixture.written, false);
    }
}

#[test]
fn non_pair_effects_dispatch_exact_writer_input_and_observe_native_result() {
    for (action, expected, succeeds) in [
        (
            CredentialOperationAction::Revoke,
            EffectCall::Delete,
            false,
        ),
        (
            CredentialOperationAction::RetiredVersionCleanup,
            EffectCall::Delete,
            false,
        ),
        (
            CredentialOperationAction::MigrateLegacy,
            EffectCall::ImportLegacy,
            true,
        ),
        (
            CredentialOperationAction::LegacySourceCleanup,
            EffectCall::DeleteLegacySource,
            true,
        ),
    ] {
        let fixture = claimed(action);
        let authority = fixture
            .claimed
            .authorize_without_secret()
            .expect("non-pair authority");

        assert_eq!(execute_non_pair_effect(authority).is_ok(), succeeds);
        assert_eq!(*fixture.calls.lock().expect("calls"), vec![expected]);
        assert_frames(&fixture.written, true);
    }
}

#[test]
fn diagnostic_write_failure_closes_after_native_invocation() {
    let fixture = claimed_with_diagnostic_failure(CredentialOperationAction::MigrateLegacy);
    let authority = fixture
        .claimed
        .authorize_without_secret()
        .expect("non-pair authority");

    assert!(execute_non_pair_effect(authority).is_err());
    assert_eq!(
        *fixture.calls.lock().expect("calls"),
        vec![EffectCall::ImportLegacy]
    );
    assert_frames(&fixture.written, false);
}
