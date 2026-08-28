use core::fmt;
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::Mutex;

use runne_api::ExecutableIdentityV1;
use zeroize::Zeroizing;

use crate::SecureStoreError;

#[cfg(test)]
pub static EXECUTABLE_TEST_LOCK: Mutex<()> = Mutex::new(());

include!("provider_credential/policy.rs");
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
include!("provider_credential/codec_layout.rs");
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
include!("provider_credential/codec.rs");
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
include!("provider_credential/codec_helpers.rs");
include!("provider_credential/store.rs");
include!("provider_credential/versioned.rs");
mod broker;
#[cfg(feature = "provider-credential-broker-writer")]
pub use broker::{
    BrokeredCreateInput, BrokeredDeleteInput, BrokeredLegacySourceDeleteInput,
    BrokeredMigrateLegacyInput, BrokeredProviderCredentialWriter,
    BrokeredWriterIdentityMigrationInput, BrokeredWriterIdentityVerificationInput,
    NativeProviderCredentialWriters, WriterIdentityMigrationObservation,
};
pub use broker::{
    CredentialReadbackObservation, ExactAbsenceReadback, ExactVersionReadback,
    NativeProviderCredentialReaderParts, NativeProviderCredentialReaders,
    ProviderCredentialDispatchMaterializer,
    ProviderCredentialReadback, ProviderCredentialVerificationMaterializer,
    ProviderCredentialVerificationReadback,
};
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows", test))]
pub mod source_update;

#[cfg(test)]
#[path = "provider_credential/source_update_tests.rs"]
mod source_update_tests;

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
pub fn generate_provider_credential_source_revision()
-> Result<ProviderCredentialSourceRevision, SecureStoreError> {
    use rand::RngCore as _;

    let mut revision = [0_u8; 16];
    rand::rngs::OsRng
        .try_fill_bytes(&mut revision)
        .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)?;
    ProviderCredentialSourceRevision::new(revision)
        .map_err(|_| SecureStoreError::ProviderCredentialOperationFailed)
}

#[cfg(test)]
mod tests;
