//! macOS owner-key entry point, intentionally fail-closed pending ACL introspection.

mod macos_acl;

use std::sync::{Mutex, OnceLock};

pub use macos_acl::CodeSignIdentity;

use super::super::{
    PendingProjectOwnerKey, ProjectOwnerAnchorFloor, ProjectOwnerKeyMaterial, ProjectOwnerKeyRef,
    ProjectOwnerKeyStore, StoreStatus,
};

static PROCESS_OPERATION_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

/// Purpose-specific macOS entry point. Persistent operations deny until the native API can
/// inspect a pre-existing item's opaque `SecAccessControl` constraints.
pub struct MacosProjectOwnerKeyStore {
    _identity: CodeSignIdentity,
}

impl MacosProjectOwnerKeyStore {
    /// Validate the current executable against its configured designated requirement.
    ///
    /// # Errors
    ///
    /// Returns [`StoreStatus::Denied`] if strict offline code-signing validation fails.
    pub fn open(identity: CodeSignIdentity) -> Result<Self, StoreStatus> {
        identity.verify_current_process()?;
        Ok(Self {
            _identity: identity,
        })
    }

    fn deny() -> Result<(), StoreStatus> {
        let _guard = PROCESS_OPERATION_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| StoreStatus::Denied)?;
        // `macos_item` may create only precisely attributed records, but its pinned Security
        // bindings cannot inspect access-control constraints of stored records. Any read,
        // update, recovery, or CAS could otherwise accept a weaker pre-existing item.
        Err(StoreStatus::Denied)
    }
}

impl ProjectOwnerKeyStore for MacosProjectOwnerKeyStore {
    fn read_active_ref(
        &self,
        repository_id: &str,
    ) -> Result<Option<ProjectOwnerKeyRef>, StoreStatus> {
        let _ = repository_id;
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn create_pending(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        repository_id: &str,
        key_epoch: u64,
        build_pop_transcript: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        let _ = (
            expected_active,
            repository_id,
            key_epoch,
            build_pop_transcript,
        );
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn create_or_resume_pending(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        repository_id: &str,
        key_epoch: u64,
        build_pop_transcript: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus> {
        let _ = (
            expected_active,
            repository_id,
            key_epoch,
            build_pop_transcript,
        );
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn sign_active(
        &self,
        expected: &ProjectOwnerKeyRef,
        transcript: &[u8],
    ) -> Result<[u8; 64], StoreStatus> {
        let _ = (expected, transcript);
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn activate_pending(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        pending: PendingProjectOwnerKey,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        let _ = (expected_active, pending);
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn commit_pending_and_floor(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        pending: PendingProjectOwnerKey,
        expected_floor: Option<&ProjectOwnerAnchorFloor>,
        replacement: &ProjectOwnerAnchorFloor,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        let _ = (expected_active, pending, expected_floor, replacement);
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn read_anchor_floor(
        &self,
        repository_id: &str,
    ) -> Result<Option<ProjectOwnerAnchorFloor>, StoreStatus> {
        let _ = repository_id;
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn write_anchor_floor(
        &self,
        expected: Option<&ProjectOwnerAnchorFloor>,
        replacement: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus> {
        let _ = (expected, replacement);
        Self::deny()
    }

    fn export_active_for_backup(
        &self,
        expected: &ProjectOwnerKeyRef,
    ) -> Result<ProjectOwnerKeyMaterial, StoreStatus> {
        let _ = expected;
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn restore_active(
        &self,
        expected_current: Option<&ProjectOwnerKeyRef>,
        material: ProjectOwnerKeyMaterial,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus> {
        let _ = (expected_current, material);
        Self::deny()?;
        Err(StoreStatus::Denied)
    }

    fn reset_after_compromise(
        &self,
        expected_active: &ProjectOwnerKeyRef,
        expected_floor: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus> {
        let _ = (expected_active, expected_floor);
        Self::deny()
    }
}
