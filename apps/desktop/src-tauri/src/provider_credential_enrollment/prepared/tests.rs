use super::*;

fn request(action: ProviderCredentialEnrollmentActionV2) -> CredentialIntentIpc {
    CredentialIntentIpc {
        provider: ProviderCredentialProviderV2::OpenAi,
        action,
        expected_revision: 7,
        renderer_generation: 3,
        verification_kind: None,
    }
}

#[test]
fn exchange_rejects_a_secret_action_without_submitted_material() {
    assert!(
        accepted_disposition(
            ProviderCredentialEnrollmentActionV2::Pair,
            SecureCredentialPromptDisposition::Confirmed,
        )
        .is_err()
    );
}

#[test]
fn exchange_rejects_confirmation_action_with_submitted_material() {
    let material = SecureCredentialMaterial::new(b"secret".to_vec()).unwrap();
    assert_eq!(
        accepted_disposition(
            ProviderCredentialEnrollmentActionV2::Revoke,
            SecureCredentialPromptDisposition::Submitted(material),
        )
        .map(|_| ()),
        Err(PreparedCredentialEnrollmentError),
    );
}

#[test]
fn native_confirmation_digest_excludes_submitted_secret_material() {
    let tag = |secret| {
        accepted_disposition(
            ProviderCredentialEnrollmentActionV2::Pair,
            SecureCredentialPromptDisposition::Submitted(
                SecureCredentialMaterial::new(secret).unwrap(),
            ),
        )
        .unwrap()
        .1
    };
    let first = native_confirmation_digest(
        request(ProviderCredentialEnrollmentActionV2::Pair),
        [1; 32],
        [2; 32],
        tag(b"first-secret".to_vec()),
    );
    let second = native_confirmation_digest(
        request(ProviderCredentialEnrollmentActionV2::Pair),
        [1; 32],
        [2; 32],
        tag(b"second-secret".to_vec()),
    );
    assert_eq!(first, second);
}

#[test]
fn exchange_retains_a_pending_exact_intent_until_dispatch() {
    let registry = CredentialIntentRegistry::new(std::time::Duration::from_secs(1)).unwrap();
    let now = Instant::now();
    let pending = issue_pending_intent(
        &registry,
        "main",
        request(ProviderCredentialEnrollmentActionV2::Pair),
        [8; 32],
        now,
    )
    .unwrap();
    assert!(pending.expires_at() > now);
    assert_eq!(registry.pending_len(), 1);
}

#[test]
fn exchange_has_no_serializable_or_credential_debug_surface() {
    let source = include_str!("../prepared.rs");
    assert!(!source.contains(concat!("derive", "(Serialize")));
    assert!(!source.contains(concat!("derive", "(Deserialize")));
    assert!(!source.contains(concat!(
        "impl Clone for ",
        "PreparedCredentialEnrollmentExchange"
    )));
    assert!(source.contains("runtime_lease: NativeCredentialEnrollmentLease"));
    assert!(source.contains("updater_lease: NativeInstalledEnrollmentLease"));
    assert!(source.contains("intent: Option<NativeCredentialIntent>"));
    assert!(source.contains("_expires: Instant"));
    assert!(source.contains("<native-only-redacted>"));
}

#[test]
fn only_completed_terminal_is_reported_as_success() {
    use runne_api::ProviderCredentialOperationStateV2 as State;

    assert!(super::runner::terminal_is_success(State::Completed));
    for state in [
        State::Failed,
        State::Expired,
        State::Cancelled,
        State::Tombstoned,
    ] {
        assert!(!super::runner::terminal_is_success(state));
    }
}
