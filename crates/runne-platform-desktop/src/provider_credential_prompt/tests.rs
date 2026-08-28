#[cfg(target_os = "linux")]
use runne_platform_ports::provider_credential_prompt::{
    SecureCredentialPromptDisposition, SecureCredentialPromptError,
};

#[cfg(target_os = "linux")]
use super::LinuxPinentryPrompt;
#[cfg(target_os = "linux")]
use super::unix::decode_pinentry_response;

#[cfg(target_os = "linux")]
#[test]
fn pinentry_response_decodes_only_one_percent_escaped_secret() {
    let disposition = decode_pinentry_response(b"OK ready\nD sk%2Dtest%25key\nOK\n").unwrap();
    let SecureCredentialPromptDisposition::Submitted(material) = disposition else {
        panic!("expected submitted material");
    };

    assert_eq!(material.into_pipe_bytes().as_bytes(), b"sk-test%key");
}

#[cfg(target_os = "linux")]
#[test]
fn pinentry_response_rejects_multiple_or_malformed_material_lines() {
    for response in [b"D key\nD other\nOK\n".as_slice(), b"D key%ZZ\nOK\n"] {
        assert!(matches!(
            decode_pinentry_response(response),
            Err(SecureCredentialPromptError::Rejected)
        ));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pinentry_adapter_requires_an_absolute_path_and_bounded_timeout() {
    assert!(
        LinuxPinentryPrompt::new(
            std::path::PathBuf::from("pinentry"),
            std::time::Duration::from_secs(1)
        )
        .is_err()
    );
    let prompt = LinuxPinentryPrompt::new(
        std::path::PathBuf::from("/bin/pinentry"),
        std::time::Duration::from_secs(30),
    )
    .unwrap();
    assert_eq!(prompt.executable(), std::path::Path::new("/bin/pinentry"));
}
