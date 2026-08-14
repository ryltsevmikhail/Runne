//! Trait and bounded-input guard for purpose-specific owner-key storage.

use crate::{
    MAX_PROJECT_OWNER_TRANSCRIPT_BYTES, PendingProjectOwnerKey, ProjectOwnerAnchorFloor,
    ProjectOwnerKeyMaterial, ProjectOwnerKeyRef, StoreStatus,
};

/// Purpose-specific native owner-key operations; no generic seed getter exists.
pub trait ProjectOwnerKeyStore: Send + Sync {
    /// Read only the active key's public metadata for a fixed repository.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status when the backend cannot prove the metadata binding.
    fn read_active_ref(
        &self,
        repository_id: &str,
    ) -> Result<Option<ProjectOwnerKeyRef>, StoreStatus>;

    /// Generate a pending key and invoke the supplied `PoP` builder exactly once.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status if the native backend cannot safely create pending material.
    fn create_pending(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        repository_id: &str,
        key_epoch: u64,
        build_pop_transcript: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus>;

    /// Create a pending key or re-open the exact matching pending record.
    ///
    /// A durable backend must resume the prior record when its expected active reference,
    /// repository, and epoch match. This permits a rotation to resume after artifact publication
    /// fails without silently generating a replacement key.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status when no matching pending record can be safely resumed.
    fn create_or_resume_pending(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        repository_id: &str,
        key_epoch: u64,
        build_pop_transcript: &mut dyn FnMut(&ProjectOwnerKeyRef) -> Result<Vec<u8>, StoreStatus>,
    ) -> Result<PendingProjectOwnerKey, StoreStatus>;

    /// Sign one bounded transcript with the exact active public reference.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status for a mismatched key, oversized transcript, or unavailable UI.
    fn sign_active(
        &self,
        expected: &ProjectOwnerKeyRef,
        transcript: &[u8],
    ) -> Result<[u8; 64], StoreStatus>;

    /// Activate a pending key only after exact active-key confirmation.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status if the expected active key or pending record differs.
    fn activate_pending(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        pending: PendingProjectOwnerKey,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus>;

    /// Atomically activate `pending` and advance the aligned local trust floor.
    ///
    /// Backends must journal this operation so a returned failure leaves either the old key and
    /// floor or the new key and floor, never a mixed pair. `expected_active` and
    /// `expected_floor` are exact CAS values; `replacement` must bind the pending key epoch.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status on a CAS, pending-token, or floor/reference-alignment mismatch.
    fn commit_pending_and_floor(
        &self,
        expected_active: Option<&ProjectOwnerKeyRef>,
        pending: PendingProjectOwnerKey,
        expected_floor: Option<&ProjectOwnerAnchorFloor>,
        replacement: &ProjectOwnerAnchorFloor,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus>;

    /// Read a repository's local owner-trust floor.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status for unsupported or inaccessible native storage.
    fn read_anchor_floor(
        &self,
        repository_id: &str,
    ) -> Result<Option<ProjectOwnerAnchorFloor>, StoreStatus>;

    /// Compare-and-set a repository's local owner-trust floor.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status for an expected-floor mismatch or inaccessible native storage.
    fn write_anchor_floor(
        &self,
        expected: Option<&ProjectOwnerAnchorFloor>,
        replacement: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus>;

    /// Export exactly the expected active key as move-only backup material.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status for a mismatched key or inaccessible native storage.
    fn export_active_for_backup(
        &self,
        expected: &ProjectOwnerKeyRef,
    ) -> Result<ProjectOwnerKeyMaterial, StoreStatus>;

    /// Restore move-only backup material after exact active-key confirmation.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status for an expected-key mismatch or inaccessible native storage.
    fn restore_active(
        &self,
        expected_current: Option<&ProjectOwnerKeyRef>,
        material: ProjectOwnerKeyMaterial,
    ) -> Result<ProjectOwnerKeyRef, StoreStatus>;

    /// Atomically remove the exact active key and aligned floor after compromise.
    ///
    /// A backend journals the reset and returns success only when both records are absent;
    /// any failure retains the all-old state. The expected reference and floor are exact CAS
    /// values and must have the same repository and epoch.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed status when either exact CAS value or their alignment mismatches.
    fn reset_after_compromise(
        &self,
        expected_active: &ProjectOwnerKeyRef,
        expected_floor: &ProjectOwnerAnchorFloor,
    ) -> Result<(), StoreStatus>;
}

/// Enforce the shared maximum before a backend signs or records pending-key `PoP` data.
///
/// # Errors
///
/// Returns [`StoreStatus::Denied`] for an oversized transcript.
pub const fn validate_transcript(transcript: &[u8]) -> Result<(), StoreStatus> {
    if transcript.is_empty() || transcript.len() > MAX_PROJECT_OWNER_TRANSCRIPT_BYTES {
        return Err(StoreStatus::Denied);
    }
    Ok(())
}
