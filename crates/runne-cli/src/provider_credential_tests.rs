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
fn credential_execution_uses_closed_outputs_and_redacts_backend_errors() {
    let resolver = FakeResolver::new();
    let mut backend = FakeBackend::default();
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Set(ProviderCredentialId::OpenAi),
            &mut b"secret".as_slice(),
            false,
            &mut backend,
            &resolver,
            true
        ),
        Err(CliError::UnsupportedCredentialBackend)
    ));
    backend.configured = true;
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
        CommandOutput::text("configured")
    );
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Delete(ProviderCredentialId::OpenAi),
            &mut b"".as_slice(),
            false,
            &mut backend,
            &resolver,
            true
        ),
        Err(CliError::UnsupportedCredentialBackend)
    ));
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

fn args(values: &[&str]) -> VecDeque<OsString> {
    values.iter().map(OsString::from).collect()
}

#[test]
fn credential_status_unsupported_outcome_is_rejected_not_exit_zero() {
    let resolver = FakeResolver::new();
    let mut backend = FakeBackend::default();
    backend.unsupported = true;
    let mut input = std::io::Cursor::new(b"sentinel-marker".to_vec());
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Status(ProviderCredentialId::OpenAi),
            &mut input,
            false,
            &mut backend,
            &resolver,
            true
        ),
        Err(CliError::UnsupportedCredentialBackend)
    ));
    assert_eq!(
        input.position(),
        0,
        "stdin must not be read for the rejection"
    );
}

#[test]
fn credential_status_without_native_backend_is_rejected_before_stdin_is_read() {
    let resolver = FakeResolver::new();
    let mut backend = FakeBackend::default();
    backend.configured = true;
    let mut input = std::io::Cursor::new(b"sentinel-marker".to_vec());
    assert!(matches!(
        execute_provider_credential_on_platform(
            ProviderCredentialCommand::Status(ProviderCredentialId::OpenAi),
            &mut input,
            false,
            &mut backend,
            &resolver,
            false
        ),
        Err(CliError::UnsupportedCredentialBackend)
    ));
    assert_eq!(
        input.position(),
        0,
        "stdin must not be read for the rejection"
    );
}

struct FakeResolver {
    _temporary: tempfile::TempDir,
    executable: std::path::PathBuf,
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
        }
    }
}

include!("provider_credential_path_tests.rs");

impl CredentialIdentityResolver for FakeResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        ProviderCredentialAccessPolicy::new(&self.executable, &self.executable)
            .map_err(|_| CliError::CredentialOperation)
    }
}

#[derive(Default)]
struct FakeBackend {
    configured: bool,
    failure: bool,
    unsupported: bool,
}

impl CredentialBackend for FakeBackend {
    fn status(
        &self,
        _id: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        if self.failure {
            return Err(SecureStoreError::OperationFailed("backend-detail".into()));
        }
        if self.unsupported {
            return Ok(CredentialOutcome::Unsupported);
        }
        Ok(if self.configured {
            CredentialOutcome::Configured
        } else {
            CredentialOutcome::Missing
        })
    }
}
#[tokio::test]
async fn broker_mode_is_not_reachable_from_async_dispatch() {
    assert!(matches!(
        run(
            vec![OsString::from(
                runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1
            )],
            OutputFormat::Text
        )
        .await,
        Err(CliError::UnknownCommand(_))
    ));
    assert!(matches!(
        run(
            vec![
                OsString::from(runne_provider::PROVIDER_CREDENTIAL_BROKER_MODE_V1),
                OsString::from("credential=secret"),
            ],
            OutputFormat::Text,
        )
        .await,
        Err(CliError::UnknownCommand(_))
    ));
}

#[test]
fn broker_secret_envelope_reader_rejects_invalid_or_oversized_eof_input() {
    for invalid in [
        b"".as_slice(),
        b"secret\n".as_slice(),
        b"secret\ntrailing".as_slice(),
    ] {
        assert!(matches!(
            read_sealed_pair_envelope(&mut std::io::Cursor::new(invalid)),
            Err(CliError::CredentialOperation)
        ));
    }
    let oversized = vec![b'a'; runne_provider::CredentialSecretEnvelopeCodec::MAX_BYTES + 1];
    assert!(matches!(
        read_sealed_pair_envelope(&mut std::io::Cursor::new(oversized)),
        Err(CliError::CredentialOperation)
    ));
}
