#![cfg(test)]

use std::sync::Arc;

use runne_provider::NativeCredentialAuthority;
use runne_secure_store::NativeProviderCredentialVersionStore;

pub(crate) type FixtureCredentialVersionStoreFactory = dyn Fn(NativeCredentialAuthority) -> Arc<dyn NativeProviderCredentialVersionStore>
    + Send
    + Sync;
