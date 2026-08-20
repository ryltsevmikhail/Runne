use ed25519_dalek::{Signer as _, SigningKey};
use runne_secure_store::{PendingProjectOwnerKey, ProjectOwnerKeyRef, StoreStatus};
use zeroize::Zeroizing;

use super::{
    AuthorityCommandRunner,
    test_support::{FakeClock, FakeFiles, FakeRng, FakeStore, FakeTty, PendingRecord},
};

impl FakeStore {
    pub(super) fn create_fresh_pending(
        &self,
        expected: Option<&ProjectOwnerKeyRef>,
        repo: &str,
        epoch: u64,
        build: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        let mut state = self.state.lock().expect("state");
        let active = state.active.clone();
        if repo != "gocode"
            || expected != active.as_ref()
            || epoch != active.as_ref().map_or(1, |key| key.key_epoch() + 1)
        {
            return Err(StoreStatus::Denied);
        }
        let seed = state.next_pending_seed;
        state.next_pending_seed = seed.checked_add(1).ok_or(StoreStatus::Denied)?;
        drop(state);
        let key = SigningKey::from_bytes(&[seed; 32]);
        let reference = ProjectOwnerKeyRef::new("gocode", key.verifying_key().to_bytes(), epoch)?;
        let transcript = build(&reference)?;
        let token = [13; 32];
        let mut state = self.state.lock().expect("state");
        state.pending_token = Some(token);
        state.pending = Some(PendingRecord {
            expected_active: expected.cloned(),
            reference: reference.clone(),
            signing_key: key.clone(),
            token,
        });
        drop(state);
        PendingProjectOwnerKey::from_backend_generated(
            reference,
            key.sign(&transcript).to_bytes(),
            Zeroizing::new(token),
            &transcript,
        )
    }
}

pub(super) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(value, "{byte:02x}").expect("String");
    }
    value
}

pub(super) fn runner<'a>(
    store: &'a FakeStore,
    files: &'a FakeFiles,
    rng: &'a mut FakeRng,
) -> AuthorityCommandRunner<'a, FakeStore, (), FakeTty, FakeRng, FakeClock, FakeFiles> {
    AuthorityCommandRunner::new(store, &(), &FakeTty, rng, &FakeClock, files)
}
