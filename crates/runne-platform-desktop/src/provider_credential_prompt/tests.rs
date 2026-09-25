use runne_platform_ports::provider_credential_prompt::{
    SecureCredentialPromptDisposition, SecureCredentialPromptError,
};

#[cfg(target_os = "linux")]
use super::LinuxGuiHostCredentialPrompt;
use super::pinentry_protocol::decode_pinentry_response;
use runne_platform_ports::provider_credential_prompt::CredentialPromptAction;
use runne_platform_ports::provider_credential_prompt::CredentialPromptProvider;

#[test]
fn pinentry_response_decodes_only_one_percent_escaped_secret() {
    let disposition = decode_pinentry_response(
        CredentialPromptProvider::OpenAi,
        CredentialPromptAction::Pair,
        b"OK ready\nOK\nOK\nD sk%2Dtest%25key\nOK\n",
    )
    .unwrap();
    let SecureCredentialPromptDisposition::Submitted(material) = disposition else {
        panic!("expected submitted material");
    };

    assert_eq!(
        material.into_pipe_bytes().into_zeroizing().as_slice(),
        b"sk-test%key"
    );
}

#[test]
fn native_oauth_prompt_accepts_large_material_with_typed_kind() {
    let mut response = b"OK ready\nOK\nOK\nD ".to_vec();
    response.extend(std::iter::repeat_n(b'o', 4097));
    response.extend_from_slice(b"\nOK\n");
    let disposition = decode_pinentry_response(
        CredentialPromptProvider::Catalog(
            runne_platform_ports::provider_credential_prompt::CredentialPromptCatalogId::OpenAiCodex,
        ),
        CredentialPromptAction::Pair,
        &response,
    )
    .unwrap();
    let SecureCredentialPromptDisposition::Submitted(material) = disposition else {
        panic!("expected submitted material");
    };
    assert_eq!(
        material.kind(),
        runne_platform_ports::provider_credential_prompt::SecureCredentialMaterialKind::NativeOAuth
    );
    assert_eq!(material.into_pipe_bytes().into_zeroizing().len(), 4097);
}

#[test]
fn pinentry_response_rejects_multiple_or_malformed_material_lines() {
    for response in [
        b"D key\nD other\nOK\n".as_slice(),
        b"D key%ZZ\nOK\n",
        b"D key\n",
        b"OK ready\nOK\nOK\nD key\n",
        b"OK ready\nOK\nOK\nD key\nOK\nOK\n",
    ] {
        assert!(
            decode_pinentry_response(
                CredentialPromptProvider::OpenAi,
                CredentialPromptAction::Pair,
                response
            )
            .is_err()
        );
    }
}

#[test]
fn pinentry_ok_only_confirms_only_non_secret_actions() {
    assert!(matches!(
        decode_pinentry_response(
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::Pair,
            b"OK ready\nOK\nOK\nOK\n"
        ),
        Err(SecureCredentialPromptError::Rejected)
    ));
    assert!(matches!(
        decode_pinentry_response(
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::Revoke,
            b"OK ready\nOK\nOK\nOK\n"
        ),
        Ok(SecureCredentialPromptDisposition::Confirmed)
    ));
    assert!(matches!(
        decode_pinentry_response(
            CredentialPromptProvider::OpenAi,
            CredentialPromptAction::Revoke,
            b"OK ready\nOK\nOK\n"
        ),
        Err(SecureCredentialPromptError::Rejected)
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn pinentry_adapter_requires_an_absolute_path_and_bounded_timeout() {
    assert!(
        LinuxGuiHostCredentialPrompt::new(
            std::path::PathBuf::from("pinentry"),
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(2),
        )
        .is_err()
    );
    let prompt = LinuxGuiHostCredentialPrompt::new(
        std::path::PathBuf::from("/bin/pinentry"),
        std::time::Duration::from_secs(30),
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(prompt.executable(), std::path::Path::new("/bin/pinentry"));
}
