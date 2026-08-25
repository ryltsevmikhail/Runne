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

    fn access(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        ProviderCredentialAccessPolicy::new(&self.executable, &self.executable)
            .map_err(|_| CliError::CredentialOperation)
    }
}

impl CredentialIdentityResolver for FakeResolver {
    fn resolve(&self) -> Result<ProviderCredentialAccessPolicy, CliError> {
        self.access()
    }
}

#[derive(Default)]
struct FakeBackend {
    configured: bool,
    unsupported: bool,
    failure: bool,
    delete_calls: usize,
    expected_access: Option<ProviderCredentialAccessPolicy>,
}

impl FakeBackend {
    fn unsupported() -> Self {
        Self {
            unsupported: true,
            ..Self::default()
        }
    }

    fn for_resolver(resolver: &FakeResolver) -> Self {
        Self {
            expected_access: Some(resolver.access().expect("resolver access")),
            ..Self::default()
        }
    }

    fn validate_access(
        &self,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        match &self.expected_access {
            Some(expected) if expected != access => Err(SecureStoreError::CredentialAccessDenied),
            _ => Ok(()),
        }
    }
}

impl CredentialBackend for FakeBackend {
    fn status(
        &self,
        _id: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<CredentialOutcome, SecureStoreError> {
        self.validate_access(access)?;
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
        _id: ProviderCredentialId,
        _credential: &ProviderCredentialMaterial,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.validate_access(access)?;
        if self.unsupported {
            return Err(SecureStoreError::UnsupportedSecureStoreBackend);
        }
        self.configured = true;
        Ok(())
    }

    fn delete(
        &mut self,
        _id: ProviderCredentialId,
        access: &ProviderCredentialAccessPolicy,
    ) -> Result<(), SecureStoreError> {
        self.validate_access(access)?;
        self.delete_calls += 1;
        self.configured = false;
        Ok(())
    }
}
