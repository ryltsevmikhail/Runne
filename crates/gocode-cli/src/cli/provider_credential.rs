#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProviderCredentialCommand {
    Set,
    Status,
    Delete,
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
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError>;
    fn store(
        &mut self,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError>;
    fn delete(&mut self) -> Result<(), SecureStoreError>;
}

impl<T: ProviderCredentialStore> CredentialBackend for T {
    fn status(
        &self,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        self.provider_credential_status(ProviderCredentialId::OpenAi, access)
            .map(|status| match status {
                ProviderCredentialStatus::Configured => CredentialOutcome::Configured,
                ProviderCredentialStatus::Missing => CredentialOutcome::Missing,
                ProviderCredentialStatus::Unsupported => CredentialOutcome::Unsupported,
            })
    }

    fn store(
        &mut self,
        credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.store_provider_credential(ProviderCredentialId::OpenAi, credential, access)
    }

    fn delete(&mut self) -> Result<(), SecureStoreError> {
        self.delete_provider_credential(ProviderCredentialId::OpenAi)
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
        .map(|directory| directory.join("gocode-daemon"))
        .ok_or(CliError::CredentialOperation)
}

fn run_provider_credential(arguments: VecDeque<OsString>) -> Result<String, CliError> {
    let mut backend = NativeProviderCredentialStore::new();
    run_provider_credential_with(
        arguments,
        &mut std::io::stdin(),
        std::io::stdin().is_terminal(),
        &mut backend,
        &NativeCredentialIdentityResolver,
        cfg!(target_os = "macos"),
    )
}

fn run_provider_credential_with(
    arguments: VecDeque<OsString>,
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
    backend: &mut impl CredentialBackend,
    resolver: &impl CredentialIdentityResolver,
    native_backend_supported: bool,
) -> Result<String, CliError> {
    let command = parse_provider_credential(arguments)?;
    execute_provider_credential_on_platform(
        command,
        stdin,
        stdin_is_terminal,
        backend,
        resolver,
        native_backend_supported,
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
            parse_openai_provider(&mut arguments)?;
            expect_token(&mut arguments, "--stdin")?;
            ProviderCredentialCommand::Set
        }
        "status" => {
            // Check for --help
            if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
                return Err(CliError::Help(PROVIDER_CREDENTIAL_STATUS_HELP.to_owned()));
            }
            parse_openai_provider(&mut arguments)?;
            ProviderCredentialCommand::Status
        }
        "delete" => {
            // Check for --help
            if peek(&arguments).is_some_and(|s| s == "--help" || s == "-h") {
                return Err(CliError::Help(PROVIDER_CREDENTIAL_DELETE_HELP.to_owned()));
            }
            parse_openai_provider(&mut arguments)?;
            ProviderCredentialCommand::Delete
        }
        _ => return Err(CliError::Usage),
    };
    expect_end(&arguments)?;
    Ok(command)
}

fn parse_openai_provider(arguments: &mut VecDeque<OsString>) -> Result<(), CliError> {
    expect_token(arguments, "--provider")?;
    expect_token(arguments, "openai")
}

fn execute_provider_credential_on_platform(
    command: ProviderCredentialCommand,
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
    backend: &mut impl CredentialBackend,
    resolver: &impl CredentialIdentityResolver,
    native_backend_supported: bool,
) -> Result<String, CliError> {
    match command {
        ProviderCredentialCommand::Set => {
            let credential = read_credential_bytes(stdin, stdin_is_terminal)?;
            if !native_backend_supported {
                return Ok(CredentialOutcome::Unsupported.stdout().to_owned());
            }
            let access = resolver.resolve()?;
            match backend.store(&credential, &access) {
                Ok(()) => Ok(CredentialOutcome::Configured.stdout().to_owned()),
                Err(
                    SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable,
                ) => Ok(CredentialOutcome::Unsupported.stdout().to_owned()),
                Err(error) => Err(map_credential_error(&error)),
            }
        }
        ProviderCredentialCommand::Status => {
            if !native_backend_supported {
                return Ok(CredentialOutcome::Unsupported.stdout().to_owned());
            }
            let access = resolver.resolve()?;
            backend
                .status(&access)
                .map(|outcome| outcome.stdout().to_owned())
                .map_err(|error| map_credential_error(&error))
        }
        ProviderCredentialCommand::Delete => {
            if !native_backend_supported {
                return Ok(CredentialOutcome::Unsupported.stdout().to_owned());
            }
            match backend.delete() {
                Ok(()) => Ok(CredentialOutcome::Missing.stdout().to_owned()),
                Err(
                    SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable,
                ) => Ok(CredentialOutcome::Unsupported.stdout().to_owned()),
                Err(error) => Err(map_credential_error(&error)),
            }
        }
    }
}

fn read_credential_bytes(
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
) -> Result<ProviderCredentialMaterial, CliError> {
    if stdin_is_terminal {
        return Err(CliError::CredentialInput);
    }
    let mut bytes = Vec::with_capacity(MAX_PROVIDER_CREDENTIAL_BYTES.saturating_add(1));
    let mut bounded = stdin.take((MAX_PROVIDER_CREDENTIAL_BYTES + 1) as u64);
    if bounded.read_to_end(&mut bytes).is_err() || bytes.len() > MAX_PROVIDER_CREDENTIAL_BYTES {
        bytes.zeroize();
        return Err(CliError::CredentialInput);
    }
    ProviderCredentialMaterial::new(bytes).map_err(|_| CliError::CredentialInput)
}

const fn map_credential_error(error: &SecureStoreError) -> CliError {
    match error {
        SecureStoreError::UnsupportedSecureStoreBackend | SecureStoreError::Unavailable => {
            CliError::UnsupportedCredentialBackend
        }
        _ => CliError::CredentialOperation,
    }
}
