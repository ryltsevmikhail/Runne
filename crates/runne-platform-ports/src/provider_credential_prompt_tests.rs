use super::*;

#[test]
fn prompt_material_rejects_empty_oversize_and_line_control() {
    for material in [
        vec![],
        vec![b'a'; MAX_CREDENTIAL_BYTES + 1],
        b"a\nb".to_vec(),
        b"a\rb".to_vec(),
        b"a\0b".to_vec(),
    ] {
        assert_eq!(
            SecureCredentialMaterial::new(material).unwrap_err(),
            SecureCredentialPromptError::Rejected
        );
    }
    assert!(SecureCredentialMaterial::new(b"correct horse battery staple".to_vec()).is_ok());
}

#[test]
fn native_oauth_material_has_a_separate_bounded_kind() {
    let material =
        SecureCredentialMaterial::from_zeroizing_native_oauth(zeroize::Zeroizing::new(vec![
            b'o';
            MAX_CREDENTIAL_BYTES
                + 1
        ]))
        .unwrap();
    assert_eq!(material.kind(), SecureCredentialMaterialKind::NativeOAuth);
    assert!(
        SecureCredentialMaterial::from_zeroizing_native_oauth(zeroize::Zeroizing::new(vec![
            b'o';
            MAX_NATIVE_OAUTH_CREDENTIAL_BYTES
                + 1
        ]),)
        .is_err()
    );
}

#[test]
fn prompt_request_rejects_zero_revision() {
    assert_eq!(
        SecureCredentialPromptRequest::new(
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::Pair,
            0
        ),
        Err(SecureCredentialPromptError::Rejected),
    );
}

#[test]
fn prompt_actions_distinguish_secret_entry_from_confirmation() {
    assert!(CredentialPromptAction::Pair.requires_secret());
    assert!(CredentialPromptAction::Rotate.requires_secret());
    assert!(!CredentialPromptAction::Revoke.requires_secret());
    assert!(!CredentialPromptAction::MigrateLegacy.requires_secret());
}
