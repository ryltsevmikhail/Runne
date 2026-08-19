use std::ops::Deref;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

pub(super) struct TestCredentialAccess {
    _directory: tempfile::TempDir,
    access: runne_secure_store::ProviderCredentialAccessPolicy,
}

impl TestCredentialAccess {
    pub(super) fn new(label: &str) -> Self {
        let directory = tempfile::Builder::new().prefix(label).tempdir().unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let executable = directory.path().join("credential-test-executable");
        std::fs::write(&executable, b"fixture executable").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        let access =
            runne_secure_store::ProviderCredentialAccessPolicy::new(&executable, &executable)
                .unwrap();
        Self {
            _directory: directory,
            access,
        }
    }
}

impl Deref for TestCredentialAccess {
    type Target = runne_secure_store::ProviderCredentialAccessPolicy;

    fn deref(&self) -> &Self::Target {
        &self.access
    }
}
