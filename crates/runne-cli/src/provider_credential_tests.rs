use super::*;
use std::cell::Cell;
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
            provider
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
fn credential_commands_reject_open_pipe_file_and_environment_forms() {
    for invalid in [
        [
            "provider",
            "credential",
            "set",
            "--provider",
            "openai",
            "--stdin",
        ]
        .as_slice(),
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
        ["provider", "credential", "status", "--provider", "other"].as_slice(),
    ] {
        assert!(parse_provider_credential(args(invalid)).is_err());
    }
}

#[test]
fn set_stores_once_and_reports_configured_only_after_readback() {
    let resolver = FakeResolver::new();
    let backend = FakeBackend::default();
    let output = execute_provider_credential_on_platform(
        ProviderCredentialCommand::Set(ProviderCredentialId::DeepSeek),
        &backend,
        &resolver,
        true,
        &|_| Ok(material(b"generated-one-off-key")),
    )
    .unwrap();
    assert_eq!(output, CommandOutput::text("configured"));
    assert_eq!(backend.stores.get(), 1);
    assert!(backend.configured.get());
}

#[test]
fn delete_removes_and_reports_missing_only_after_readback() {
    let resolver = FakeResolver::new();
    let backend = FakeBackend {
        configured: Cell::new(true),
        ..FakeBackend::default()
    };
    let output = execute_provider_credential_on_platform(
        ProviderCredentialCommand::Delete(ProviderCredentialId::DeepSeek),
        &backend,
        &resolver,
        true,
        &|_| panic!("delete must not read a secret"),
    )
    .unwrap();
    assert_eq!(output, CommandOutput::text("missing"));
    assert_eq!(backend.deletes.get(), 1);
    assert!(!backend.configured.get());
}

#[test]
fn set_does_not_report_success_when_readback_stays_missing() {
    let resolver = FakeResolver::new();
    let backend = FakeBackend::default();
    backend.drop_store.set(true);
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::DeepSeek),
            &backend,
            &resolver,
            true,
            &|_| Ok(material(b"generated-one-off-key")),
        ),
        Err(CliError::CredentialOperation)
    ));
}

#[test]
fn credential_execution_redacts_backend_errors_and_never_reports_unsupported_as_success() {
    let resolver = FakeResolver::new();
    let backend = FakeBackend::default();
    backend.failure.set(true);
    let error = execute_provider_credential_on_platform(
        ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
        &backend,
        &resolver,
        true,
        &|_| Ok(material(b"generated-one-off-key")),
    )
    .unwrap_err()
    .to_string();
    assert_eq!(error, "provider credential operation failed");
    assert!(!error.contains("backend-detail"));

    let unsupported = FakeBackend::default();
    unsupported.unsupported.set(true);
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Status(ProviderCredentialId::OpenAi),
            &unsupported,
            &resolver,
            true,
            &|_| panic!("status must not read a secret"),
        ),
        Err(CliError::UnsupportedCredentialBackend)
    ));
}

#[test]
fn unsupported_native_backend_rejects_before_identity_or_secret_read() {
    let resolver = FakeResolver::new();
    let backend = FakeBackend::default();
    for command in [
        ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
        ProviderCredentialCommand::Delete(ProviderCredentialId::OpenAi),
        ProviderCredentialCommand::Status(ProviderCredentialId::OpenAi),
    ] {
        assert!(matches!(
            execute_provider_credential_on_platform(
                command,
                &backend,
                &resolver,
                false,
                &|_| panic!("secret must not be read"),
            ),
            Err(CliError::UnsupportedCredentialBackend)
        ));
    }
    assert_eq!(resolver.calls.get(), 0);
}

fn material(bytes: &[u8]) -> ProviderCredentialMaterial {
    ProviderCredentialMaterial::new(bytes.to_vec()).expect("test material")
}

fn args(values: &[&str]) -> VecDeque<OsString> {
    values.iter().map(OsString::from).collect()
}

struct FakeResolver {
    _temporary: tempfile::TempDir,
    executable: std::path::PathBuf,
    calls: Cell<usize>,
}

impl FakeResolver {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("temporary executable directory");
        #[cfg(unix)]
        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o700))
            .expect("restrict temporary executable directory");
        let executable = temporary.path().join("runne-test-executable");
        let current = std::env::current_exe().expect("current CLI test executable");
        std::fs::copy(current, &executable).expect("copy test executable");
        #[cfg(unix)]
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .expect("restrict test executable");
        Self {
            _temporary: temporary,
            executable,
            calls: Cell::new(0),
        }
    }
}

impl CredentialIdentityResolver for FakeResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        self.calls.set(self.calls.get() + 1);
        ProviderCredentialAccessPolicy::new(&self.executable, &self.executable)
            .map_err(|_| CliError::CredentialOperation)
    }
}

#[derive(Default)]
struct FakeBackend {
    configured: Cell<bool>,
    failure: Cell<bool>,
    unsupported: Cell<bool>,
    drop_store: Cell<bool>,
    stores: Cell<usize>,
    deletes: Cell<usize>,
}

impl CredentialBackend for FakeBackend {
    fn status(
        &self,
        _id: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        if self.failure.get() {
            return Err(SecureStoreError::OperationFailed("backend-detail".into()));
        }
        if self.unsupported.get() {
            return Ok(CredentialOutcome::Unsupported);
        }
        Ok(if self.configured.get() {
            CredentialOutcome::Configured
        } else {
            CredentialOutcome::Missing
        })
    }

    fn store(
        &self,
        _id: ProviderCredentialId,
        _material: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.stores.set(self.stores.get() + 1);
        if self.failure.get() {
            return Err(SecureStoreError::OperationFailed("backend-detail".into()));
        }
        self.configured.set(!self.drop_store.get());
        Ok(())
    }

    fn delete(&self, _id: ProviderCredentialId) -> Result<(), SecureStoreError> {
        self.deletes.set(self.deletes.get() + 1);
        if self.failure.get() {
            return Err(SecureStoreError::OperationFailed("backend-detail".into()));
        }
        self.configured.set(false);
        Ok(())
    }
}
