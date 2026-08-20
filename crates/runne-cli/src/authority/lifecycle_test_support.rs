use ed25519_dalek::{Signer as _, SigningKey};
use runne_secure_store::{
    PendingProjectOwnerKey, ProjectOwnerAnchorFloor, ProjectOwnerKeyMaterial, ProjectOwnerKeyRef,
    ProjectOwnerKeyStore, StoreStatus,
};
use sha2::{Digest as _, Sha256};
use std::{collections::BTreeMap, sync::Mutex};
use zeroize::Zeroizing;

use super::{AuthorityClock, AuthorityFiles, AuthorityRng, AuthorityTty};
use crate::CliError;

pub(super) struct State {
    pub(super) active: Option<ProjectOwnerKeyRef>,
    pub(super) floor: Option<ProjectOwnerAnchorFloor>,
    pub(super) pending_token: Option<[u8; 32]>,
    pub(super) pending: Option<PendingRecord>,
    pub(super) next_pending_seed: u8,
    pub(super) backup_exports: usize,
    pub(super) restores: usize,
    pub(super) reset_calls: usize,
    pub(super) sign_calls: usize,
    pub(super) fail_next_commit: bool,
}
pub(super) struct PendingRecord {
    pub(super) expected_active: Option<ProjectOwnerKeyRef>,
    pub(super) reference: ProjectOwnerKeyRef,
    pub(super) signing_key: SigningKey,
    pub(super) token: [u8; 32],
}
pub(super) struct FakeStore {
    pub(super) state: Mutex<State>,
    signing_key: SigningKey,
}
impl FakeStore {
    pub(super) fn new() -> Self {
        Self {
            state: Mutex::new(State {
                active: None,
                floor: None,
                pending_token: None,
                pending: None,
                next_pending_seed: 7,
                backup_exports: 0,
                restores: 0,
                reset_calls: 0,
                sign_calls: 0,
                fail_next_commit: false,
            }),
            signing_key: SigningKey::from_bytes(&[7; 32]),
        }
    }
}
impl ProjectOwnerKeyStore for FakeStore {
    fn read_active_ref(&self, repo: &str) -> Result<Option<ProjectOwnerKeyRef>, StoreStatus> {
        if repo != "gocode" {
            return Err(StoreStatus::Denied);
        }
        Ok(self.state.lock().expect("state").active.clone())
    }
    fn create_pending(
        &self,
        expected: Option<&ProjectOwnerKeyRef>,
        repo: &str,
        epoch: u64,
        build: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        let active = self.state.lock().expect("state").active.clone();
        if repo != "gocode"
            || expected != active.as_ref()
            || epoch != active.as_ref().map_or(1, |key| key.key_epoch() + 1)
        {
            return Err(StoreStatus::Denied);
        }
        self.create_fresh_pending(expected, repo, epoch, build)
    }
    fn create_or_resume_pending(
        &self,
        expected: Option<&ProjectOwnerKeyRef>,
        repo: &str,
        epoch: u64,
        build: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        let state = self.state.lock().expect("state");
        if repo != "gocode" || expected != state.active.as_ref() {
            return Err(StoreStatus::Denied);
        }
        if let Some(pending) = state.pending.as_ref() {
            if pending.expected_active.as_ref() != expected
                || pending.reference.key_epoch() != epoch
            {
                return Err(StoreStatus::Denied);
            }
            let transcript = build(&pending.reference)?;
            return PendingProjectOwnerKey::from_backend_generated(
                pending.reference.clone(),
                pending.signing_key.sign(&transcript).to_bytes(),
                Zeroizing::new(pending.token),
                &transcript,
            );
        }
        drop(state);
        self.create_fresh_pending(expected, repo, epoch, build)
    }
    fn sign_active(
        &self,
        expected: &ProjectOwnerKeyRef,
        transcript: &[u8],
    ) -> Result<[u8; 64], StoreStatus> {
        if self.state.lock().expect("state").active.as_ref() != Some(expected) {
            return Err(StoreStatus::Denied);
        }
        self.state.lock().expect("state").sign_calls += 1;
        Ok(self.signing_key.sign(transcript).to_bytes())
    }
    fn activate_pending(
        &self,
        _: Option<&ProjectOwnerKeyRef>,
        _: PendingProjectOwnerKey,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        Err(StoreStatus::Denied)
    }
    fn commit_pending_and_floor(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        pending: PendingProjectOwnerKey,
        expected_floor: Option<&ProjectOwnerAnchorFloor>,
        replacement: &ProjectOwnerAnchorFloor,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        let mut state = self.state.lock().expect("state");
        let reference = pending.key_ref().clone();
        if state.fail_next_commit {
            state.fail_next_commit = false;
            return Err(StoreStatus::Denied);
        }
        if expected_active != state.active.as_ref()
            || expected_floor != state.floor.as_ref()
            || state.pending_token.as_ref().is_none_or(|token| {
                !pending.matches_backend_token(token)
                    || replacement.highest_key_epoch() != reference.key_epoch()
            })
        {
            return Err(StoreStatus::Denied);
        }
        state.pending_token = None;
        state.pending = None;
        state.active = Some(reference.clone());
        state.floor = Some(replacement.clone());
        drop(state);
        Ok(reference)
    }
    fn read_anchor_floor(
        &self,
        repo: &str,
    ) -> Result<Option<ProjectOwnerAnchorFloor>, StoreStatus> {
        if repo != "gocode" {
            return Err(StoreStatus::Denied);
        }
        Ok(self.state.lock().expect("state").floor.clone())
    }
    fn write_anchor_floor(
        &self,
        _: Option<&ProjectOwnerAnchorFloor>,
        _: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus> {
        Err(StoreStatus::Denied)
    }
    fn export_active_for_backup(
        &self,
        expected: &ProjectOwnerKeyRef,
    ) -> Result<ProjectOwnerKeyMaterial, StoreStatus> {
        if self.state.lock().expect("state").active.as_ref() != Some(expected) {
            return Err(StoreStatus::Denied);
        }
        self.state.lock().expect("state").backup_exports += 1;
        ProjectOwnerKeyMaterial::from_backup_seed(expected.clone(), Zeroizing::new([7; 32]))
    }
    fn restore_active(
        &self,
        expected: Option<&ProjectOwnerKeyRef>,
        material: ProjectOwnerKeyMaterial,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        let mut state = self.state.lock().expect("state");
        if state.active.as_ref() != expected {
            return Err(StoreStatus::Denied);
        }
        let reference = material.key_ref().clone();
        state.active = Some(reference.clone());
        state.restores += 1;
        drop(state);
        Ok(reference)
    }
    fn reset_after_compromise(
        &self,
        active: &ProjectOwnerKeyRef,
        floor: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus> {
        let mut state = self.state.lock().expect("state");
        state.reset_calls += 1;
        if state.active.as_ref() != Some(active) || state.floor.as_ref() != Some(floor) {
            return Err(StoreStatus::Denied);
        }
        state.active = None;
        state.floor = None;
        drop(state);
        Ok(())
    }
}
pub(super) struct FakeTty;
impl AuthorityTty for FakeTty {
    fn confirm(&self, _: &str, _: &str) -> Result<(), CliError> {
        Ok(())
    }
}
pub(super) struct FakeRng;
impl AuthorityRng for FakeRng {}
impl runne_project_owner_authority::BackupRng for FakeRng {
    fn fill_bytes(
        &mut self,
        bytes: &mut [u8],
    ) -> Result<(), runne_project_owner_authority::AuthorityError> {
        bytes.fill(9);
        Ok(())
    }
}
pub(super) struct FakeClock;
impl AuthorityClock for FakeClock {
    fn utc_rfc3339_seconds(&self) -> Result<String, CliError> {
        Ok("2026-08-13T00:00:00Z".into())
    }
}
pub(super) struct FakeFiles {
    pub(super) fail_on_write: Mutex<Option<usize>>,
    pub(super) write_count: Mutex<usize>,
    pub(super) fail_reads_after_write: bool,
    pub(super) bytes: Mutex<BTreeMap<String, Vec<u8>>>,
}
impl AuthorityFiles for FakeFiles {
    fn validate_repo_public_output(&self, path: &str) -> Result<(), CliError> {
        if path.starts_with('/') || path.split('/').any(|part| matches!(part, "" | "." | "..")) {
            return Err(CliError::AuthorityUsage);
        }
        Ok(())
    }
    fn create_new_repo_public(&self, path: &str, bytes: &[u8]) -> Result<(), CliError> {
        let mut count = self.write_count.lock().expect("write count");
        *count += 1;
        if *self.fail_on_write.lock().expect("write failure") == Some(*count) {
            return Err(CliError::AuthorityUnavailable);
        }
        drop(count);
        self.bytes
            .lock()
            .expect("bytes")
            .insert(path.into(), bytes.to_vec());
        Ok(())
    }
    fn create_new_or_exact_repo_public(&self, path: &str, bytes: &[u8]) -> Result<(), CliError> {
        let existing = self.bytes.lock().expect("bytes").get(path).cloned();
        if let Some(existing) = existing {
            return if existing == bytes {
                Ok(())
            } else {
                Err(CliError::AuthorityArtifactExists)
            };
        }
        self.create_new_repo_public(path, bytes)
    }
    fn read_repo_public(&self, path: &str) -> Result<Vec<u8>, CliError> {
        if self.fail_reads_after_write && *self.write_count.lock().expect("write count") != 0 {
            return Err(CliError::AuthorityArtifactIo);
        }
        self.bytes
            .lock()
            .expect("bytes")
            .get(path)
            .cloned()
            .ok_or(CliError::AuthorityUnavailable)
    }
    fn bounded_nofollow_read(&self, path: &str) -> Result<Vec<u8>, CliError> {
        self.read_repo_public(path)
    }
    fn validate_external_path(&self, path: &str, _: &std::path::Path) -> Result<String, CliError> {
        if path.starts_with("repo/") || !path.starts_with('/') {
            return Err(CliError::AuthorityUnavailable);
        }
        Ok(super::test_pending::hex(&Sha256::digest(path.as_bytes())))
    }
    fn create_new_external_0600(&self, path: &str, bytes: &[u8]) -> Result<(), CliError> {
        *self.write_count.lock().expect("write count") += 1;
        let mut saved = self.bytes.lock().expect("bytes");
        if saved.contains_key(path) {
            return Err(CliError::AuthorityUnavailable);
        }
        saved.insert(path.into(), bytes.to_vec());
        drop(saved);
        Ok(())
    }
}
