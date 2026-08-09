use core::fmt;
use std::path::{Path, PathBuf};

use gocode_api::ExecutableIdentityV1;
use zeroize::Zeroizing;

use crate::SecureStoreError;

include!("provider_credential/policy.rs");
#[cfg(any(target_os = "macos", test))]
include!("provider_credential/codec.rs");
#[cfg(any(target_os = "macos", test))]
include!("provider_credential/codec_helpers.rs");
include!("provider_credential/store.rs");
include!("provider_credential/versioned.rs");

#[cfg(target_os = "macos")]
fn generate_provider_credential_source_revision()
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
