#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderCredentialCommand {
    Set(ProviderCredentialId),
    Status(ProviderCredentialId),
    Delete(ProviderCredentialId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CredentialOutcome {
    Configured,
    Missing,
    Unsupported,
}

impl CredentialOutcome {
    const fn stdout(self) -> &'static str {
        match self {
            Self::Configured => "configured",
            Self::Missing => "missing",
            Self::Unsupported => "unsupported",
        }
    }
}

trait CredentialBackend {
    fn status(
        &self,
        id: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError>;

    fn store(
        &self,
        id: ProviderCredentialId,
        material: &runne_secure_store::ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;

    fn delete(&self, id: ProviderCredentialId) -> Result<(), SecureStoreError>;
}

impl<T: ProviderCredentialStore> CredentialBackend for T {
    fn status(
        &self,
        id: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        self.provider_credential_status(id, access)
            .map(|status| match status {
                ProviderCredentialStatus::Configured => CredentialOutcome::Configured,
                ProviderCredentialStatus::Missing => CredentialOutcome::Missing,
                ProviderCredentialStatus::Unsupported => CredentialOutcome::Unsupported,
            })
    }

    fn store(
        &self,
        id: ProviderCredentialId,
        material: &runne_secure_store::ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.store_provider_credential(id, material, access)
    }

    fn delete(&self, id: ProviderCredentialId) -> Result<(), SecureStoreError> {
        self.delete_provider_credential(id)
    }
}

trait CredentialIdentityResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError>;
}

struct NativeCredentialIdentityResolver;

impl CredentialIdentityResolver for NativeCredentialIdentityResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        #[cfg(target_os = "macos")]
        {
            let writer = std::env::current_exe().map_err(|_| CliError::CredentialOperation)?;
            let writer =
                std::fs::canonicalize(writer).map_err(|_| CliError::CredentialOperation)?;
            let reader = packaged_daemon_path(&writer)?;
            ProviderCredentialAccessPolicy::new(&writer, &reader)
                .map_err(|_| CliError::CredentialOperation)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(CliError::UnsupportedCredentialBackend)
        }
    }
}

#[cfg(target_os = "macos")]
fn packaged_daemon_path(writer: &std::path::Path) -> Result<std::path::PathBuf, CliError> {
    writer
        .parent()
        .map(|directory| directory.join("runned"))
        .ok_or(CliError::CredentialOperation)
}

fn run_provider_credential_with(
    arguments: VecDeque<OsString>,
    backend: &impl CredentialBackend,
    resolver: &impl CredentialIdentityResolver,
    native_backend_supported: bool,
    read_secret: &impl Fn(ProviderCredentialId) -> Result<runne_secure_store::ProviderCredentialMaterial, CliError>,
) -> Result<CommandOutput, CliError> {
    let command = parse_provider_credential(arguments)?;
    execute_provider_credential_on_platform(
        command,
        backend,
        resolver,
        native_backend_supported,
        read_secret,
    )
}

fn parse_provider_credential(
    mut arguments: VecDeque<OsString>,
) -> Result<ProviderCredentialCommand, CliError> {
    expect_token(&mut arguments, "provider")?;

    // Check for --help after "provider"
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(PROVIDER_HELP.to_owned()));
    }

    expect_token(&mut arguments, "credential")?;

    // Check for --help after "credential"
    if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
        return Err(CliError::Help(PROVIDER_CREDENTIAL_HELP.to_owned()));
    }

    let operation = pop_string(&mut arguments)?;
    let command = match operation.as_str() {
        "set" => {
            // Check for --help
            if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
                return Err(CliError::Help(PROVIDER_CREDENTIAL_SET_HELP.to_owned()));
            }
            let provider = parse_provider(&mut arguments)?;
            ProviderCredentialCommand::Set(provider)
        }
        "status" => {
            // Check for --help
            if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
                return Err(CliError::Help(PROVIDER_CREDENTIAL_STATUS_HELP.to_owned()));
            }
            let provider = parse_provider(&mut arguments)?;
            ProviderCredentialCommand::Status(provider)
        }
        "delete" => {
            // Check for --help
            if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
                return Err(CliError::Help(PROVIDER_CREDENTIAL_DELETE_HELP.to_owned()));
            }
            let provider = parse_provider(&mut arguments)?;
            ProviderCredentialCommand::Delete(provider)
        }
        _ => return Err(CliError::Usage),
    };
    expect_end(&arguments)?;
    Ok(command)
}

fn parse_provider(arguments: &mut VecDeque<OsString>) -> Result<ProviderCredentialId, CliError> {
    expect_token(arguments, "--provider")?;
    match pop_string(arguments)?.as_str() {
        "openai" => Ok(ProviderCredentialId::OpenAi),
        "deepseek" => Ok(ProviderCredentialId::DeepSeek),
        _ => Err(CliError::Usage),
    }
}

fn execute_provider_credential_on_platform(
    command: ProviderCredentialCommand,
    backend: &impl CredentialBackend,
    resolver: &impl CredentialIdentityResolver,
    native_backend_supported: bool,
    read_secret: &impl Fn(ProviderCredentialId) -> Result<runne_secure_store::ProviderCredentialMaterial, CliError>,
) -> Result<CommandOutput, CliError> {
    match command {
        ProviderCredentialCommand::Set(id) => {
            require_native(native_backend_supported)?;
            let access = resolver.resolve()?;
            let material = read_secret(id)?;
            backend
                .store(id, &material, &access)
                .map_err(|error| map_credential_error(&error))?;
            require_outcome(backend.status(id, &access), CredentialOutcome::Configured)?;
            Ok(CommandOutput::text(CredentialOutcome::Configured.stdout()))
        }
        ProviderCredentialCommand::Delete(id) => {
            require_native(native_backend_supported)?;
            let access = resolver.resolve()?;
            backend
                .delete(id)
                .map_err(|error| map_credential_error(&error))?;
            require_outcome(backend.status(id, &access), CredentialOutcome::Missing)?;
            Ok(CommandOutput::text(CredentialOutcome::Missing.stdout()))
        }
        ProviderCredentialCommand::Status(id) => {
            // Unsupported provider/capability is a rejection before any input
            // is read; it must never render as a success outcome (exit 0).
            require_native(native_backend_supported)?;
            let access = resolver.resolve()?;
            match backend
                .status(id, &access)
                .map_err(|error| map_credential_error(&error))?
            {
                CredentialOutcome::Unsupported => Err(CliError::UnsupportedCredentialBackend),
                outcome => Ok(CommandOutput::text(outcome.stdout())),
            }
        }
    }
}

const fn require_native(supported: bool) -> Result<(), CliError> {
    if supported {
        Ok(())
    } else {
        Err(CliError::UnsupportedCredentialBackend)
    }
}

fn require_outcome(
    actual: Result<CredentialOutcome, SecureStoreError>,
    expected: CredentialOutcome,
) -> Result<(), CliError> {
    match actual.map_err(|error| map_credential_error(&error))? {
        outcome if outcome == expected => Ok(()),
        _ => Err(CliError::CredentialOperation),
    }
}

const fn map_credential_error(error: &SecureStoreError) -> CliError {
    match error {
        SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable => {
            CliError::UnsupportedCredentialBackend
        }
        _ => CliError::CredentialOperation,
    }
}
