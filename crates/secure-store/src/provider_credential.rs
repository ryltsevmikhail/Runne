use core::fmt;
use std::path::{Path, PathBuf};

use gocode_api::ExecutableIdentityV1;
use zeroize::Zeroizing;

use crate::SecureStoreError;

include!("provider_credential/policy.rs");
#[cfg(target_os = "macos")]
include!("provider_credential/codec.rs");
include!("provider_credential/store.rs");
include!("provider_credential/versioned.rs");

#[cfg(all(test, target_os = "macos"))]
mod tests;
