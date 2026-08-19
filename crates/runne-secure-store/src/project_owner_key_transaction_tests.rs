#![cfg(all(test, not(target_os = "macos")))]

use std::sync::Mutex;

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::{
    PendingProjectOwnerKey, ProjectOwnerAnchorFloor, ProjectOwnerKeyMaterial, ProjectOwnerKeyRef,
    ProjectOwnerKeyStore, StoreStatus,
};

#[derive(Clone, Copy)]
enum Failure {
    None,
    BeforeJournal,
    AfterJournal,
    BeforeSwap,
    BeforeRecovery,
    ResetBeforeJournal,
    ResetAfterJournal,
}
struct Journal {
    active: Option<ProjectOwnerKeyRef>,
    floor: Option<ProjectOwnerAnchorFloor>,
    token: [u8; 32],
    pending: ProjectOwnerKeyRef,
    completed: bool,
    failure: Failure,
}
struct Fake(Mutex<Journal>);
fn key(seed: u8, epoch: u64) -> ProjectOwnerKeyRef {
    ProjectOwnerKeyRef::new(
        "runne",
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
        epoch,
    )
    .expect("key")
}
fn floor(epoch: u64, byte: u8) -> ProjectOwnerAnchorFloor {
    ProjectOwnerAnchorFloor::new("runne", epoch, [byte; 32]).expect("floor")
}
fn pending(reference: ProjectOwnerKeyRef, token: [u8; 32]) -> PendingProjectOwnerKey {
    PendingProjectOwnerKey::from_backend_generated(
        reference,
        [0; 64],
        Zeroizing::new(token),
        b"pop",
    )
    .expect("pending")
}
impl Fake {
    const fn new(
        active: ProjectOwnerKeyRef,
        floor: ProjectOwnerAnchorFloor,
        pending: ProjectOwnerKeyRef,
        token: [u8; 32],
    ) -> Self {
        Self(Mutex::new(Journal {
            active: Some(active),
            floor: Some(floor),
            token,
            pending,
            completed: false,
            failure: Failure::None,
        }))
    }
}
impl ProjectOwnerKeyStore for Fake {
    fn read_active_ref(
        &self,
        repository_id: &str,
    ) -> Result<Option<ProjectOwnerKeyRef>, StoreStatus> {
        let s = self.0.lock().expect("lock");
        if repository_id == "runne" {
            Ok(s.active.clone())
        } else {
            Err(StoreStatus::Denied)
        }
    }
    fn create_pending(
        &self,
        _: Option<&ProjectOwnerKeyRef>,
        _: &str,
        _: u64,
        _: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn create_or_resume_pending(
        &self,
        _: Option<&ProjectOwnerKeyRef>,
        _: &str,
        _: u64,
        _: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn sign_active(&self, _: &ProjectOwnerKeyRef, _: &[u8]) -> Result<[u8; 64], StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn activate_pending(
        &self,
        _: Option<&ProjectOwnerKeyRef>,
        _: PendingProjectOwnerKey,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn commit_pending_and_floor(
        &self,
        expected: Option<&ProjectOwnerKeyRef>,
        pending: PendingProjectOwnerKey,
        expected_floor: Option<&ProjectOwnerAnchorFloor>,
        replacement: &ProjectOwnerAnchorFloor,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        let mut s = self.0.lock().expect("lock");
        if !pending.matches_backend_token(&s.token)
            || pending.key_ref() != &s.pending
            || replacement.repository_id() != "runne"
            || replacement.highest_key_epoch() != pending.key_ref().key_epoch()
        {
            return Err(StoreStatus::Denied);
        }
        if s.completed
            && expected == s.active.as_ref()
            && expected_floor == s.floor.as_ref()
            && replacement == s.floor.as_ref().expect("floor")
        {
            return Ok(s.pending.clone());
        }
        if expected != s.active.as_ref()
            || expected_floor != s.floor.as_ref()
            || !matches!(
                s.failure,
                Failure::None | Failure::ResetBeforeJournal | Failure::ResetAfterJournal
            )
        {
            return Err(StoreStatus::Denied);
        }
        s.active = Some(s.pending.clone());
        s.floor = Some(replacement.clone());
        s.completed = true;
        Ok(s.pending.clone())
    }
    fn read_anchor_floor(
        &self,
        repository_id: &str,
    ) -> Result<Option<ProjectOwnerAnchorFloor>, StoreStatus> {
        if repository_id != "runne" {
            return Err(StoreStatus::Denied);
        }
        Ok(self.0.lock().expect("lock").floor.clone())
    }
    fn write_anchor_floor(
        &self,
        _: Option<&ProjectOwnerAnchorFloor>,
        _: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn export_active_for_backup(
        &self,
        _: &ProjectOwnerKeyRef,
    ) -> Result<ProjectOwnerKeyMaterial, StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn restore_active(
        &self,
        _: Option<&ProjectOwnerKeyRef>,
        _: ProjectOwnerKeyMaterial,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        Err(StoreStatus::Unsupported)
    }
    fn reset_after_compromise(
        &self,
        expected: &ProjectOwnerKeyRef,
        expected_floor: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus> {
        let mut s = self.0.lock().expect("lock");
        if s.active.as_ref() != Some(expected)
            || s.floor.as_ref() != Some(expected_floor)
            || matches!(
                s.failure,
                Failure::ResetBeforeJournal | Failure::ResetAfterJournal
            )
        {
            return Err(StoreStatus::Denied);
        }
        s.active = None;
        s.floor = None;
        drop(s);
        Ok(())
    }
}
#[test]
fn commit_is_all_old_or_all_new_and_replay_is_idempotent() {
    let (old, old_floor, next, next_floor, token) =
        (key(1, 1), floor(1, 1), key(2, 2), floor(2, 2), [9; 32]);
    let fake = Fake::new(old.clone(), old_floor.clone(), next.clone(), token);
    for phase in [
        Failure::BeforeJournal,
        Failure::AfterJournal,
        Failure::BeforeSwap,
        Failure::BeforeRecovery,
    ] {
        fake.0.lock().expect("lock").failure = phase;
        assert_eq!(
            fake.commit_pending_and_floor(
                Some(&old),
                pending(next.clone(), token),
                Some(&old_floor),
                &next_floor
            ),
            Err(StoreStatus::Denied)
        );
        assert_eq!(fake.read_active_ref("runne"), Ok(Some(old.clone())));
        assert_eq!(fake.read_anchor_floor("runne"), Ok(Some(old_floor.clone())));
    }
    fake.0.lock().expect("lock").failure = Failure::None;
    assert_eq!(
        fake.commit_pending_and_floor(
            Some(&old),
            pending(next.clone(), token),
            Some(&old_floor),
            &next_floor
        ),
        Ok(next.clone())
    );
    assert_eq!(fake.read_active_ref("runne"), Ok(Some(next.clone())));
    assert_eq!(
        fake.read_anchor_floor("runne"),
        Ok(Some(next_floor.clone()))
    );
    assert_eq!(
        fake.commit_pending_and_floor(
            Some(&next),
            pending(next.clone(), token),
            Some(&next_floor),
            &next_floor
        ),
        Ok(next)
    );
}
#[test]
fn token_cas_and_reset_fail_closed() {
    let (old, old_floor, next, next_floor, token) =
        (key(1, 1), floor(1, 1), key(2, 2), floor(2, 2), [9; 32]);
    let fake = Fake::new(old.clone(), old_floor.clone(), next.clone(), token);
    assert_eq!(
        fake.commit_pending_and_floor(None, pending(next, [8; 32]), Some(&old_floor), &next_floor),
        Err(StoreStatus::Denied)
    );
    for phase in [Failure::ResetBeforeJournal, Failure::ResetAfterJournal] {
        fake.0.lock().expect("lock").failure = phase;
        assert_eq!(
            fake.reset_after_compromise(&old, &old_floor),
            Err(StoreStatus::Denied)
        );
        assert_eq!(fake.read_active_ref("runne"), Ok(Some(old.clone())));
    }
    fake.0.lock().expect("lock").failure = Failure::None;
    assert_eq!(fake.reset_after_compromise(&old, &old_floor), Ok(()));
    assert_eq!(fake.read_active_ref("runne"), Ok(None));
    assert_eq!(fake.read_anchor_floor("runne"), Ok(None));
}
