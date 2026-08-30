//! Keychain-backed producer for threshold-signed desktop updater metadata.

#![allow(clippy::missing_errors_doc)]

mod input;
mod issuer;
mod key_store;
mod output;

pub use input::{UpdateMetadataDraft, UpdatePublicKeyManifest};
pub use issuer::{ProducerError, issue_metadata};
pub use key_store::{KeySlot, UpdateSigningKeyStore};

use std::path::Path;

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
