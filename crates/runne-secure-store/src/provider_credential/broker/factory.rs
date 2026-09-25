use std::sync::Arc;

use runne_provider::{
    CredentialAuthorityPair, CredentialEnrollmentStoreAuthority, CredentialLifecycleAuthority,
};

use super::dispatch::{ProviderCredentialDispatchMaterializer, VersionStoreDispatchMaterializer};
use super::readback::{ProviderCredentialReadback, VersionStoreReadback};
use super::verification_readback::{
    NativeProviderCredentialVerificationMaterializer, ProviderCredentialVerificationMaterializer,
    ProviderCredentialVerificationReadback, VersionStoreVerificationReadback,
};
use crate::{NativeProviderCredentialStore, ProviderCredentialAccessPolicy};

/// Creates the reader-only native materializer for store-issued remote leases.
///
/// The enrollment authority must be the same pair that issued the lease; this
/// check occurs before the native keyring is read.
#[must_use]
pub fn native_verification_materializer(
    authority: CredentialEnrollmentStoreAuthority,
    access: ProviderCredentialAccessPolicy,
) -> Arc<dyn ProviderCredentialVerificationMaterializer> {
    Arc::new(NativeProviderCredentialVerificationMaterializer::new(
        authority, access,
    ))
}

/// Reader-only parts exposed to daemon composition.
pub type NativeProviderCredentialReaderParts = (
    CredentialLifecycleAuthority,
    Arc<dyn ProviderCredentialReadback>,
    Arc<dyn ProviderCredentialDispatchMaterializer>,
    Arc<dyn ProviderCredentialVerificationReadback>,
);

/// Construction-separated native readers for daemon composition.
///
/// The concrete native backend and its verifier authority remain private to
/// this crate. Consumers receive only the lifecycle issuer and narrow reader
/// trait objects, never a writer-capable native-store value.
pub struct NativeProviderCredentialReaders {
    lifecycle_authority: CredentialLifecycleAuthority,
    readback: Arc<dyn ProviderCredentialReadback>,
    dispatch: Arc<dyn ProviderCredentialDispatchMaterializer>,
    verification: Arc<dyn ProviderCredentialVerificationReadback>,
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
            NativeProviderCredentialStore::new_versioned(native_authority.clone()),
            access.clone(),
        );
        let verification = VersionStoreVerificationReadback::new(
            NativeProviderCredentialStore::new_versioned(native_authority),
            access,
        );
        Self {
            lifecycle_authority,
            readback: Arc::new(readback),
            dispatch: Arc::new(dispatch),
            verification: Arc::new(verification),
        }
    }

    /// Separates the store-owned issuer from the reader-only values.
    #[must_use]
    pub fn into_parts(self) -> NativeProviderCredentialReaderParts {
        (
            self.lifecycle_authority,
            self.readback,
            self.dispatch,
            self.verification,
        )
    }
}

#[cfg(test)]
mod tests {
    use runne_provider::{
        BeginCredentialVerification, CredentialAuthorityPair, CredentialBindingDigest,
        CredentialEnrollmentAuthorityPair, CredentialFence, CredentialLease,
        CredentialLifecycleRevision, CredentialOperationId, CredentialReadinessRevision,
        CredentialVerificationKind, CredentialVerifierRevision, CredentialVersionRef, ProviderId,
    };

    use super::*;
    use crate::{ProviderCredentialDispatchRead, SecureStoreError};

    #[test]
    fn stale_dispatch_capability_cannot_materialize() {
        let (_, _, materializer, _) = NativeProviderCredentialReaders::new(access()).into_parts();
        let (foreign, _) = CredentialAuthorityPair::new().split();
        let reference = CredentialVersionRef::new(ProviderId::new("openai").unwrap(), 1).unwrap();
        let capability =
            foreign.issue_dispatch(CredentialLease::new(reference, [1; 16], i64::MAX, 1).unwrap());
        let read = ProviderCredentialDispatchRead::new(
            &capability,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            [1; 32],
        )
        .unwrap();

        assert_eq!(
            materializer
                .materialize_active(read)
                .err()
                .expect("remote lease rejected"),
            SecureStoreError::CredentialAccessDenied
        );
    }

    #[test]
    fn verification_reader_rejects_remote_leases_before_native_access() {
        let (_, _, _, reader) = NativeProviderCredentialReaders::new(access()).into_parts();

        assert_eq!(
            reader.verify_local(&remote_lease()).unwrap_err(),
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

    fn remote_lease() -> runne_provider::CredentialVerificationLease {
        let provider = ProviderId::new("openai").unwrap();
        let reference = CredentialVersionRef::new(provider.clone(), 1).unwrap();
        let begin = BeginCredentialVerification::new(
            CredentialOperationId::from_bytes([4; 16]).unwrap(),
            None,
            provider,
            CredentialVerificationKind::Remote,
            CredentialLifecycleRevision::new(1).unwrap(),
            CredentialFence::new(1).unwrap(),
            CredentialReadinessRevision::new(1).unwrap(),
            CredentialBindingDigest::from_measured([4; 32]).unwrap(),
            CredentialBindingDigest::from_measured([5; 32]).unwrap(),
            CredentialVerifierRevision::new(1).unwrap(),
            1,
            2,
        )
        .unwrap();
        let (store, _) = CredentialEnrollmentAuthorityPair::new().split();
        store.issue_credential_verification_lease(begin, reference)
    }
}
