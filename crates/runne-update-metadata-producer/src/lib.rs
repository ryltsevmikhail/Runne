//! Keychain-backed producer for threshold-signed desktop updater metadata.

#![allow(clippy::missing_errors_doc)]

mod input;
mod issuer;
mod key_store;
#[cfg(target_os = "linux")]
mod linux_key_store;
#[cfg(target_os = "linux")]
mod linux_secret_service;
mod output;

pub use input::{UpdateMetadataDraft, UpdatePublicKeyManifest};
pub use issuer::{ProducerError, issue_metadata};
pub use key_store::{KeySlot, UpdateSigningKeyStore};

use std::path::Path;

#[allow(clippy::missing_const_for_fn)]
pub fn initialize_dev_keyset(path: &Path, keychain_ref: &Path) -> Result<(), ProducerError> {
    #[cfg(all(target_os = "macos", debug_assertions, feature = "dev-keyset-init"))]
    {
        let manifest = key_store::MacKeychainStore::initialize(keychain_ref)?;
        output::publish_json(path, &manifest)
    }
    #[cfg(not(all(target_os = "macos", debug_assertions, feature = "dev-keyset-init")))]
    {
        let _ = (path, keychain_ref);
        Err(ProducerError::KeyStore)
    }
}

#[cfg(all(target_os = "linux", debug_assertions, feature = "dev-keyset-init"))]
pub fn initialize_linux_dev_keyset(path: &Path) -> Result<(), ProducerError> {
    linux_key_store::initialize_and_publish(path, output::publish_json)
}

pub fn issue_from_files(
    draft: &Path,
    output_path: &Path,
    keychain_ref: &Path,
) -> Result<(), ProducerError> {
    let draft: UpdateMetadataDraft = input::read_json(draft)?;
    #[cfg(target_os = "macos")]
    let store = key_store::MacKeychainStore::open(keychain_ref)?;
    #[cfg(not(target_os = "macos"))]
    let store = {
        let _ = keychain_ref;
        key_store::UnavailableKeyStore
    };
    let metadata = issue_metadata(&draft, &store)?;
    output::publish_json(output_path, &metadata)
}

#[cfg(target_os = "linux")]
pub fn issue_from_files_secret_service(
    draft: &Path,
    output_path: &Path,
) -> Result<(), ProducerError> {
    let draft: UpdateMetadataDraft = input::read_json(draft)?;
    let store = linux_key_store::SecretServiceStore::open()?;
    let metadata = issue_metadata(&draft, &store)?;
    output::publish_json(output_path, &metadata)
}
