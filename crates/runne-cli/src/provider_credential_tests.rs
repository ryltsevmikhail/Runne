use super::*;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn credential_commands_accept_only_the_exact_provider_forms() {
    assert_provider_forms("openai", ProviderCredentialId::OpenAi);
    assert_provider_forms("deepseek", ProviderCredentialId::DeepSeek);
}

fn assert_provider_forms(provider: &str, id: ProviderCredentialId) {
    assert!(matches!(
        parse_provider_credential(args(&[
            "provider",
            "credential",
            "set",
            "--provider",
            provider,
            "--stdin"
        ])),
        Ok(ProviderCredentialCommand::Set(parsed)) if parsed == id
    ));
    assert!(matches!(
        parse_provider_credential(args(&[
            "provider",
            "credential",
            "status",
            "--provider",
            provider
        ])),
        Ok(ProviderCredentialCommand::Status(parsed)) if parsed == id
    ));
    assert!(matches!(
        parse_provider_credential(args(&[
            "provider",
            "credential",
            "delete",
            "--provider",
            provider
        ])),
        Ok(ProviderCredentialCommand::Delete(parsed)) if parsed == id
    ));
}

#[test]
fn credential_commands_reject_open_or_ambiguous_provider_forms() {
    for invalid in [
        [
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--value",
        ]
        .as_slice(),
        [
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--env",
        ]
        .as_slice(),
        [
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--file",
        ]
        .as_slice(),
        ["provider", "credential", "set", "--provider", "openai"].as_slice(),
        ["provider", "credential", "status", "--provider", "other"].as_slice(),
    ] {
        assert!(parse_provider_credential(args(invalid)).is_err());
    }
}

#[test]
fn credential_input_rejects_secret_shaped_invalid_bytes_and_bounds_reads() {
    for mut invalid in [b"".as_slice(), b"a\0b", b"a\rb", b"a\nb"] {
        assert!(read_credential_bytes(&mut invalid, false).is_err());
    }
    assert!(read_credential_bytes(&mut vec![b'a'; 4_097].as_slice(), false).is_err());
    assert!(read_credential_bytes(&mut vec![b'a'; 4_096].as_slice(), false).is_ok());
    assert!(read_credential_bytes(&mut b"credential".as_slice(), true).is_err());
}

#[test]
fn credential_execution_uses_closed_outputs_and_redacts_backend_errors() {
    let resolver = FakeResolver::new();
    let mut backend = FakeBackend::default();
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
            &mut b"secret".as_slice(),
            false,
            &mut backend,
            &resolver,
            true
        )
        .unwrap(),
        "configured"
    );
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Status(ProviderCredentialId::OpenAi),
            &mut b"".as_slice(),
            false,
            &mut backend,
            &resolver,
            true
        )
        .unwrap(),
        "configured"
    );
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Delete(ProviderCredentialId::OpenAi),
            &mut b"".as_slice(),
            false,
            &mut backend,
            &resolver,
            true
        )
        .unwrap(),
        "missing"
    );
    backend.failure = true;
    let error = execute_provider_credential_on_platform(
        ProviderCredentialCommand::Status(ProviderCredentialId::OpenAi),
        &mut b"sensitive-marker".as_slice(),
        false,
        &mut backend,
        &resolver,
        true,
    )
    .unwrap_err()
    .to_string();
    assert_eq!(error, "provider credential operation failed");
    assert!(!error.contains("sensitive-marker"));
    assert!(!error.contains("backend-detail"));
}

#[test]
fn credential_delete_double_rejects_a_substituted_policy_before_side_effect() {
    let resolver = FakeResolver::new();
    let mismatched = FakeResolver::new();
    let mut backend = FakeBackend::for_resolver(&mismatched);

    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Delete(ProviderCredentialId::OpenAi),
            &mut b"".as_slice(),
            false,
            &mut backend,
            &resolver,
            true,
        ),
        Err(CliError::CredentialOperation)
    ));
    assert!(!backend.configured);
    assert_eq!(backend.delete_calls, 0);
}

#[test]
fn unsupported_backend_never_reports_persistence() {
    let mut backend = FakeBackend::unsupported();
    let resolver = FakeResolver::new();
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
            &mut b"secret".as_slice(),
            false,
            &mut backend,
            &resolver,
            true
        )
        .unwrap(),
        "unsupported"
    );
    assert!(!backend.configured);
}

#[test]
fn unsupported_platform_validates_set_input_before_returning_unsupported() {
    let mut backend = FakeBackend::default();
    let resolver = FakeResolver::new();
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
            &mut b"invalid\ncredential".as_slice(),
            false,
            &mut backend,
            &resolver,
            false
        ),
        Err(CliError::CredentialInput)
    ));
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
            &mut b"credential".as_slice(),
            true,
            &mut backend,
            &resolver,
            false
        ),
        Err(CliError::CredentialInput)
    ));
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
            &mut vec![b'x'; 4_096].as_slice(),
            false,
            &mut backend,
            &resolver,
            false
        )
        .unwrap(),
        "unsupported"
    );
    assert!(!backend.configured);
}

fn args(values: &[&str]) -> VecDeque<OsString> {
    values.iter().map(OsString::from).collect()
}

include!("provider_credential_test_doubles.rs");
include!("provider_credential_path_tests.rs");
