#![cfg(all(target_os = "macos", feature = "provider-credential-broker-writer"))]

use runne_native_enrollment_authority::AuthenticatedProviderCredentialWriterSession;
use runne_secure_store::{NativeProviderCredentialWriters, SecureStoreError};

#[test]
fn production_writer_factory_consumes_only_one_authenticated_session() {
    let factory: fn(
        AuthenticatedProviderCredentialWriterSession,
    ) -> Result<NativeProviderCredentialWriters, SecureStoreError> =
        NativeProviderCredentialWriters::from_authenticated_session;
    let _ = factory;
}
