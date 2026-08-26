use std::sync::Arc;

use runne_provider::{CredentialAuthorityPair, CredentialLifecycleAuthority};

use super::readback::{
    ProviderCredentialDispatchMaterializer, ProviderCredentialReadback,
    VersionStoreDispatchMaterializer, VersionStoreReadback,
};
use crate::{NativeProviderCredentialStore, ProviderCredentialAccessPolicy};

/// Construction-separated native readers for daemon composition.
///
/// The concrete native backend and its verifier authority remain private to
/// this crate. Consumers receive only the lifecycle issuer and narrow reader
/// trait objects, never a writer-capable native-store value.
pub struct NativeProviderCredentialReaders {
    lifecycle_authority: CredentialLifecycleAuthority,
    readback: Arc<dyn ProviderCredentialReadback>,
    dispatch: Arc<dyn ProviderCredentialDispatchMaterializer>,
}

impl NativeProviderCredentialReaders {
    /// Creates release-bound native readers for one runtime authority domain.
    #[must_use]
    pub fn new(access: ProviderCredentialAccessPolicy) -> Self {
        let (lifecycle_authority, native_authority) = CredentialAuthorityPair::new().split();
        let readback = VersionStoreReadback::new(
            NativeProviderCredentialStore::new_versioned(native_authority.clone()),
            access.clone(),
        );
        let dispatch = VersionStoreDispatchMaterializer::new(
            NativeProviderCredentialStore::new_versioned(native_authority),
            access,
        );
        Self {
            lifecycle_authority,
            readback: Arc::new(readback),
            dispatch: Arc::new(dispatch),
        }
    }

    /// Separates the store-owned issuer from the two reader-only values.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialLifecycleAuthority,
        Arc<dyn ProviderCredentialReadback>,
        Arc<dyn ProviderCredentialDispatchMaterializer>,
    ) {
        (self.lifecycle_authority, self.readback, self.dispatch)
    }
}

#[cfg(test)]
mod tests {
    use runne_provider::{
        CredentialAuthorityPair, CredentialLease, CredentialVersionRef, ProviderId,
    };

    use super::*;
    use crate::SecureStoreError;

    #[test]
    fn stale_dispatch_capability_cannot_materialize() {
        let (_, _, materializer) = NativeProviderCredentialReaders::new(access()).into_parts();
        let (foreign, _) = CredentialAuthorityPair::new().split();
        let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap();
        let capability =
            foreign.issue_dispatch(CredentialLease::new(reference, [1; 16], i64::MAX, 1).unwrap());

        assert_eq!(
            materializer.materialize_active(&capability).unwrap_err(),
            SecureStoreError::CredentialAccessDenied
        );
    }

    fn access() -> ProviderCredentialAccessPolicy {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("runne");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o500)).unwrap();
        }
        ProviderCredentialAccessPolicy::new(&executable, &executable).unwrap()
    }
}
