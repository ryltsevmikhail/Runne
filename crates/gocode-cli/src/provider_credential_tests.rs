use super::*;

#[test]
fn credential_commands_accept_only_the_exact_openai_forms() {
    assert!(matches!(
        parse_provider_credential(args(&[
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--stdin"
        ])),
        Ok(ProviderCredentialCommand::Set)
    ));
    assert!(matches!(
        parse_provider_credential(args(&[
            "provider",
            "credential",
            "status",
            "--provider",
            "openai"
        ])),
        Ok(ProviderCredentialCommand::Status)
    ));
    assert!(matches!(
        parse_provider_credential(args(&[
            "provider",
            "credential",
            "delete",
            "--provider",
            "openai"
        ])),
        Ok(ProviderCredentialCommand::Delete)
    ));
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
    let resolver = FakeResolver;
    let mut backend = FakeBackend::default();
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set,
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
            ProviderCredentialCommand::Status,
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
            ProviderCredentialCommand::Delete,
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
        ProviderCredentialCommand::Status,
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
fn unsupported_backend_never_reports_persistence() {
    let mut backend = FakeBackend::unsupported();
    assert_eq!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set,
            &mut b"secret".as_slice(),
            false,
            &mut backend,
            &FakeResolver,
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
    let resolver = FakeResolver;
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set,
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
            ProviderCredentialCommand::Set,
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
            ProviderCredentialCommand::Set,
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

struct FakeResolver;

include!("provider_credential_path_tests.rs");

impl CredentialIdentityResolver for FakeResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        let current = std::env::current_exe().map_err(|_| CliError::CredentialOperation)?;
        ProviderCredentialAccessPolicy::new(&current, &current)
            .map_err(|_| CliError::CredentialOperation)
    }
}

#[derive(Default)]
struct FakeBackend {
    configured: bool,
    unsupported: bool,
    failure: bool,
}

impl FakeBackend {
    fn unsupported() -> Self {
        Self {
            unsupported: true,
            ..Self::default()
        }
    }
}

impl CredentialBackend for FakeBackend {
    fn status(
        &self,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        if self.failure {
            return Err(SecureStoreError::OperationFailed("backend-detail".into()));
        }
        Ok(if self.unsupported {
            CredentialOutcome::Unsupported
        } else if self.configured {
            CredentialOutcome::Configured
        } else {
            CredentialOutcome::Missing
        })
    }

    fn store(
        &mut self,
        _credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        if self.unsupported {
            return Err(SecureStoreError::UnsupportedSecureStoreBackend);
        }
        self.configured = true;
        Ok(())
    }

    fn delete(&mut self) -> Result<(), SecureStoreError> {
        self.configured = false;
        Ok(())
    }
}
