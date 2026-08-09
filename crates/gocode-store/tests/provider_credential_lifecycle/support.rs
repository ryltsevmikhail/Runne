use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
};

use gocode_provider::{
    CredentialLease, CredentialLifecycleError, CredentialVersionRef, PrepareCredentialVersion,
    ProviderCredentialVersionStore, ProviderId, RevokeCredentialVersion,
};
use gocode_store::provider::SqliteProviderCredentialLifecycleStore;

pub const OWNER_A: [u8; 16] = [0xA1; 16];
pub const OWNER_B: [u8; 16] = [0xB2; 16];

pub fn version(number: u64) -> CredentialVersionRef {
    CredentialVersionRef::new(ProviderId::new("openai").unwrap(), number).unwrap()
}

pub fn lease(
    reference: CredentialVersionRef,
    owner: [u8; 16],
    expires_at: i64,
    fence: u64,
) -> CredentialLease {
    CredentialLease::new(reference, owner, expires_at, fence).unwrap()
}

pub fn store(path: &Path) -> SqliteProviderCredentialLifecycleStore {
    SqliteProviderCredentialLifecycleStore::open(path).unwrap()
}

pub fn prepare(store: &SqliteProviderCredentialLifecycleStore, reference: CredentialVersionRef) {
    assert_eq!(
        store
            .create_prepared(PrepareCredentialVersion::new(reference.clone()))
            .unwrap(),
        reference
    );
}

pub fn revoke(
    store: &SqliteProviderCredentialLifecycleStore,
    reference: CredentialVersionRef,
    fence: u64,
) {
    store
        .revoke_and_fence(RevokeCredentialVersion::new(reference, fence).unwrap())
        .unwrap();
}

#[derive(Default)]
pub struct FixtureNative {
    values: Mutex<HashMap<CredentialVersionRef, Vec<u8>>>,
    deleted: Mutex<HashMap<CredentialVersionRef, usize>>,
}

impl FixtureNative {
    pub fn create(&self, reference: CredentialVersionRef, bytes: &[u8]) {
        let mut values = self.values.lock().unwrap();
        match values.get(&reference) {
            Some(existing) => assert_eq!(existing, bytes),
            None => {
                values.insert(reference, bytes.to_vec());
            }
        }
    }

    pub fn delete(&self, reference: CredentialVersionRef) {
        if self.values.lock().unwrap().remove(&reference).is_some() {
            *self.deleted.lock().unwrap().entry(reference).or_default() += 1;
        }
    }

    pub fn configured_versions(&self) -> usize {
        self.values.lock().unwrap().len()
    }

    pub fn delete_calls(&self, reference: &CredentialVersionRef) -> usize {
        self.deleted
            .lock()
            .unwrap()
            .get(reference)
            .copied()
            .unwrap_or(0)
    }
}

pub fn finish_deletions(
    store: &SqliteProviderCredentialLifecycleStore,
    native: &Arc<FixtureNative>,
    now: i64,
) -> Result<(), CredentialLifecycleError> {
    for reference in store.reconcile(now)?.native_deletions() {
        native.delete(reference.clone());
        store.complete_native_delete(reference.clone())?;
    }
    Ok(())
}
