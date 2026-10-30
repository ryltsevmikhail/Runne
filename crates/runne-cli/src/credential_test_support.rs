use super::{
    CliError, CredentialBackend, CredentialIdentityResolver, CredentialOutcome, OsString,
    OutputFormat, ProcessOutcome, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, SecureStoreError, VecDeque, process_outcome,
    run_provider_credential_with,
};
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

pub struct ProcessResult {
    pub outcome: ProcessOutcome,
    pub resolver_calls: usize,
}

pub fn run(
    arguments: Vec<OsString>,
    input: &mut impl Read,
    stdin_is_terminal: bool,
    scenario: &str,
) -> ProcessResult {
    let mut secret = Vec::new();
    if stdin_is_terminal {
        input.read_to_end(&mut secret).expect("read test secret");
    }
    let mut backend = Backend {
        configured: std::cell::Cell::new(scenario == "status"),
        failure: scenario == "backend-error" || scenario == "set-backend-error",
        drop_store: scenario == "drop-store",
    };
    let resolver = Resolver::new(
        scenario == "resolver-error" || scenario == "set-resolver-error" || scenario == "delete",
    );
    let read_secret = |_: ProviderCredentialId| {
        if !stdin_is_terminal {
            return Err(CliError::CredentialRequiresTerminal);
        }
        ProviderCredentialMaterial::new(secret.clone()).map_err(|_| CliError::CredentialOperation)
    };
    let result = run_provider_credential_with(
        VecDeque::from(arguments),
        &mut backend,
        &resolver,
        true,
        &read_secret,
    );
    ProcessResult {
        outcome: process_outcome(result, OutputFormat::Text),
        resolver_calls: resolver.calls.get(),
    }
}

struct Resolver {
    fail: bool,
    calls: std::cell::Cell<usize>,
    _temporary: tempfile::TempDir,
    executable: std::path::PathBuf,
}

impl Resolver {
    fn new(fail: bool) -> Self {
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
            fail,
            calls: std::cell::Cell::new(0),
            _temporary: temporary,
            executable,
        }
    }
}

impl CredentialIdentityResolver for Resolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        self.calls.set(self.calls.get() + 1);
        if self.fail {
            return Err(CliError::CredentialOperation);
        }
        ProviderCredentialAccessPolicy::new(&self.executable, &self.executable)
            .map_err(|_| CliError::CredentialOperation)
    }
}

struct Backend {
    configured: std::cell::Cell<bool>,
    failure: bool,
    drop_store: bool,
}

impl CredentialBackend for Backend {
    fn status(
        &self,
        _id: ProviderCredentialId,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        if self.failure {
            return Err(SecureStoreError::OperationFailed(
                "backend-detail".to_owned(),
            ));
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
        if self.failure {
            return Err(SecureStoreError::OperationFailed(
                "backend-detail".to_owned(),
            ));
        }
        self.configured.set(!self.drop_store);
        Ok(())
    }

    fn delete(&self, _id: ProviderCredentialId) -> Result<(), SecureStoreError> {
        if self.failure {
            return Err(SecureStoreError::OperationFailed(
                "backend-detail".to_owned(),
            ));
        }
        self.configured.set(false);
        Ok(())
    }
}
