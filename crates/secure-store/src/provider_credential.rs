use core::fmt;
use std::path::{Path, PathBuf};

use gocode_api::ExecutableIdentityV1;
use zeroize::Zeroizing;

use crate::SecureStoreError;

include!("provider_credential/policy.rs");
include!("provider_credential/codec.rs");
include!("provider_credential/store.rs");

#[cfg(test)]
mod tests;
