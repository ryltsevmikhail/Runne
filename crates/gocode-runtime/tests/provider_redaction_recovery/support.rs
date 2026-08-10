use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use gocode_provider::{
    CredentialMatcher, DispatchAttemptId, NativeSecretRef, ScannerError,
    ScannerCheckpoint, ScannerTerminalDisposition, ScannerUncertainReason, SecureStoreError, TailBinding,
    WithheldTailStore,
};
use gocode_runtime::provider_redaction::{
    ProviderRedactionError, ProviderRedactionRecovery, ScannerRecoveryPersistence,
};
use gocode_runtime::provider_redaction::{ScannerRecoveryPersistenceError, ScannerRecoveryRecord};
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
    fn tail_count(&self) -> usize { self.tails.lock().unwrap().len() }
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
    fn delete_tail(&self, reference: &NativeSecretRef) -> Result<(), SecureStoreError> {
        self.tails.lock().unwrap().remove(reference);
        Ok(())
    }
    fn purge_orphaned_tails(&self, binding: TailBinding, retained: Option<NativeSecretRef>) -> Result<(), SecureStoreError> {
        self.tails.lock().unwrap().retain(|reference, (stored, _)| {
            stored.attempt_id() != binding.attempt_id() || Some(*reference) == retained
        });
        Ok(())
    }
}

fn binding() -> TailBinding {
    TailBinding::new(DispatchAttemptId::from_bytes([7; 16]), 9, 11, 13, 1, 0).unwrap()
}

fn stores() -> (tempfile::TempDir, SqliteProviderRecoveryStore) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("provider.sqlite");
    drop(SqliteProviderDispatchStore::open(&path).unwrap());
    let recovery = SqliteProviderRecoveryStore::open(&path, [1; 16]).unwrap();
    (directory, recovery)
}

fn assert_no_publication(store: &SqliteProviderRecoveryStore) {
    assert_eq!(store.canonical_publication_counts().unwrap(), (0, 0));
}

#[derive(Clone, Copy)]
enum FailPhase { Persist, Advance }

struct FailingPersistence<'a> {
    inner: &'a SqliteProviderRecoveryStore,
    phase: FailPhase,
}

impl ScannerRecoveryPersistence for FailingPersistence<'_> {
    fn persist_checkpoint(&self, checkpoint: ScannerCheckpoint) -> Result<(), ScannerRecoveryPersistenceError> {
        if matches!(self.phase, FailPhase::Persist) { Err(ScannerRecoveryPersistenceError::Unavailable) } else { self.inner.persist_checkpoint(checkpoint) }
    }
    fn advance_checkpoint(&self, checkpoint: ScannerCheckpoint) -> Result<(), ScannerRecoveryPersistenceError> {
        if matches!(self.phase, FailPhase::Advance) { Err(ScannerRecoveryPersistenceError::Unavailable) } else { self.inner.advance_checkpoint(checkpoint) }
    }
    fn advance_final_checkpoint(&self, checkpoint: ScannerCheckpoint) -> Result<(), ScannerRecoveryPersistenceError> {
        if matches!(self.phase, FailPhase::Advance) { Err(ScannerRecoveryPersistenceError::Unavailable) } else { self.inner.advance_final_checkpoint(checkpoint) }
    }
    fn commit_terminal(&self, binding: TailBinding, disposition: ScannerTerminalDisposition) -> Result<ScannerTerminalDisposition, ScannerRecoveryPersistenceError> {
        self.inner.commit_terminal(binding, disposition)
    }
    fn load(&self, attempt: DispatchAttemptId) -> Result<Option<ScannerRecoveryRecord>, ScannerRecoveryPersistenceError> {
        self.inner.load(attempt)
    }
}
