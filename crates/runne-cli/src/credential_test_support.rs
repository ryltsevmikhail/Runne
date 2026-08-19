use super::{
    CliError, CredentialBackend, CredentialIdentityResolver, CredentialOutcome, OsString,
    OutputFormat, ProcessOutcome, ProviderCredentialAccessPolicy, ProviderCredentialId,
    ProviderCredentialMaterial, Read, SecureStoreError, VecDeque, process_outcome,
    run_provider_credential_with,
};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

pub struct ProcessResult {
    pub outcome: ProcessOutcome,
    pub delete_calls: usize,
    pub resolver_calls: usize,
    pub store_calls: usize,
    pub store_received_stdin_secret: bool,
}

pub fn run(
    arguments: Vec<OsString>,
    stdin: &mut impl Read,
    stdin_is_terminal: bool,
    scenario: &str,
) -> ProcessResult {
    let mut backend = Backend {
        configured: scenario == "status",
        failure: scenario == "backend-error" || scenario == "set-backend-error",
        delete_calls: 0,
        store_calls: 0,
        store_received_stdin_secret: false,
    };
    let resolver = Resolver::new(
        scenario == "resolver-error" || scenario == "set-resolver-error" || scenario == "delete",
    );
    let result = run_provider_credential_with(
        VecDeque::from(arguments),
        stdin,
        stdin_is_terminal,
        &mut backend,
        &resolver,
        true,
    );
    ProcessResult {
        outcome: process_outcome(result, OutputFormat::Text),
        delete_calls: backend.delete_calls,
        resolver_calls: resolver.calls.get(),
        store_calls: backend.store_calls,
        store_received_stdin_secret: backend.store_received_stdin_secret,
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
    configured: bool,
    failure: bool,
    delete_calls: usize,
    store_calls: usize,
    store_received_stdin_secret: bool,
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
        Ok(if self.configured {
            CredentialOutcome::Configured
        } else {
            CredentialOutcome::Missing
        })
    }

    fn store(
        &mut self,
        _id: ProviderCredentialId,
        credential: &ProviderCredentialMaterial,
        _access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.store_calls += 1;
        self.store_received_stdin_secret = credential.with_bytes(|bytes| bytes == b"stdin-secret");
        if self.failure {
            return Err(SecureStoreError::OperationFailed(
                "backend-detail".to_owned(),
            ));
        }
        self.configured = true;
        Ok(())
    }

    fn delete(&mut self, _id: ProviderCredentialId) -> Result<(), SecureStoreError> {
        self.delete_calls += 1;
        self.configured = false;
        Ok(())
    }
}
