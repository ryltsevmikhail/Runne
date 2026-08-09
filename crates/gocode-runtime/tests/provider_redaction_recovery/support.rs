use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use gocode_provider::{
    CredentialMatcher, DispatchAttemptId, NativeSecretRef, ScannerError,
    ScannerTerminalDisposition, ScannerUncertainReason, SecureStoreError, TailBinding,
    WithheldTailStore,
};
use gocode_runtime::provider_redaction::{ProviderRedactionRecovery, ScannerRecoveryPersistence};
use gocode_store::provider::{SqliteProviderDispatchStore, SqliteProviderRecoveryStore};
use zeroize::Zeroizing;

const SECRET: &[u8] = b"credential-token";
type StoredTail = (TailBinding, Zeroizing<Vec<u8>>);

struct FixtureMatcher { epoch: u64, unavailable: bool, scanner_unavailable: bool }

impl CredentialMatcher for FixtureMatcher {
    fn epoch(&self) -> Result<u64, ScannerError> {
        (!self.unavailable).then_some(self.epoch).ok_or(ScannerError::MatcherUnavailable)
    }
    fn maximum_match_len(&self) -> Result<usize, ScannerError> {
        (!self.unavailable).then_some(SECRET.len()).ok_or(ScannerError::MatcherUnavailable)
    }
    fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError> {
        if self.scanner_unavailable { return Err(ScannerError::ScannerUnavailable); }
        Ok(bytes.windows(SECRET.len()).any(|window| window == SECRET))
    }
}

#[derive(Default)]
struct MemoryTailStore {
    next: Mutex<u8>,
    tails: Mutex<HashMap<NativeSecretRef, StoredTail>>,
    corrupt: Mutex<HashSet<NativeSecretRef>>,
    unavailable: Mutex<bool>,
}

impl MemoryTailStore {
    fn remove(&self, reference: NativeSecretRef) { self.tails.lock().unwrap().remove(&reference); }
    fn corrupt(&self, reference: NativeSecretRef) { self.corrupt.lock().unwrap().insert(reference); }
    fn make_unavailable(&self) { *self.unavailable.lock().unwrap() = true; }
}

impl WithheldTailStore for MemoryTailStore {
    fn put_tail(&self, binding: TailBinding, bytes: Zeroizing<Vec<u8>>) -> Result<NativeSecretRef, SecureStoreError> {
        let mut next = self.next.lock().unwrap();
        *next = next.checked_add(1).ok_or(SecureStoreError::Unavailable)?;
        let mut id = [0; 16]; id[15] = *next;
        let reference = NativeSecretRef::new(id, 1, binding.digest())?;
        self.tails.lock().unwrap().insert(reference, (binding, bytes));
        Ok(reference)
    }
    fn load_tail(&self, reference: &NativeSecretRef, binding: TailBinding) -> Result<Zeroizing<Vec<u8>>, SecureStoreError> {
        if *self.unavailable.lock().unwrap() { return Err(SecureStoreError::Unavailable); }
        if self.corrupt.lock().unwrap().contains(reference) { return Err(SecureStoreError::Corrupt); }
        let tails = self.tails.lock().unwrap();
        let (stored_binding, bytes) = tails.get(reference).ok_or(SecureStoreError::NotFound)?;
        if *stored_binding != binding || reference.binding_digest() != &binding.digest() { return Err(SecureStoreError::BindingMismatch); }
        Ok(Zeroizing::new(bytes.to_vec()))
    }
}

fn binding() -> TailBinding {
    TailBinding::new(DispatchAttemptId::from_bytes([7; 16]), 9, 11, 13, 1, 0).unwrap()
}

fn stores() -> (tempfile::TempDir, SqliteProviderRecoveryStore) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite");
    drop(SqliteProviderDispatchStore::open(&path).unwrap());
    let recovery = SqliteProviderRecoveryStore::open(&path).unwrap();
    (directory, recovery)
}

fn assert_no_publication(store: &SqliteProviderRecoveryStore) {
    assert_eq!(store.canonical_publication_counts().unwrap(), (0, 0));
}
