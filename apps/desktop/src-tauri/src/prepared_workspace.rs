use std::collections::hash_map::Entry;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use runne_platform_desktop::{ProtectedRootHandleAdmission, VerifiedRootHandle, WorkspaceId};
use serde::{Deserialize, Serialize};

use crate::directory_selection::{
    SelectionError, random_reference, valid_binding, valid_reference,
};
use crate::renderer_generation::{DirectorySelectionState, SharedSelectionState};

// The transport admission offer is valid for 30 seconds; reserve a margin for
// the blocking transfer so a host reference cannot outlive its daemon claim.
const MAX_PREPARED_TTL: Duration = Duration::from_secs(25);

/// Opaque renderer-safe reference to one host-retained root admission.
pub struct PreparedWorkspaceRef(String);

impl Serialize for PreparedWorkspaceRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PreparedWorkspaceRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        valid_reference(&value)
            .then_some(Self(value))
            .ok_or_else(|| serde::de::Error::custom("prepared workspace rejected"))
    }
}

impl fmt::Debug for PreparedWorkspaceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedWorkspaceRef(<redacted>)")
    }
}

/// Renderer-safe presentation for a prepared local root.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedWorkspaceSummary {
    display_name: &'static str,
}

impl PreparedWorkspaceSummary {
    #[must_use]
    pub const fn selected_folder() -> Self {
        Self {
            display_name: "Selected folder",
        }
    }
}

/// Opaque response emitted to the renderer after protected admission.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PreparedWorkspaceResponse {
    reference: PreparedWorkspaceRef,
    summary: PreparedWorkspaceSummary,
}

impl PreparedWorkspaceResponse {
    #[must_use]
    pub const fn new(reference: PreparedWorkspaceRef) -> Self {
        Self {
            reference,
            summary: PreparedWorkspaceSummary::selected_folder(),
        }
    }
}

#[allow(dead_code)] // Task 8 consumes this host-only prepared entry.
pub struct PreparedWorkspaceEntry {
    pub(crate) window: String,
    pub(crate) generation: u64,
    pub(crate) request: String,
    pub(super) root: Option<VerifiedRootHandle>,
    pub(super) admission: Option<ProtectedRootHandleAdmission>,
    workspace_id: WorkspaceId,
    expected_version: u64,
    expires_at: Instant,
    pub(super) operation_permit: Option<tokio::sync::OwnedMutexGuard<()>>,
    pub(super) prepared_open: Option<runne_app_core::PreparedWorkspaceOpen>,
    pub(super) phase: PreparedWorkspacePhase,
}

// These state types remain crate-internal while sibling root modules access them.
#[allow(clippy::redundant_pub_crate)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PreparedWorkspacePhase {
    Ready,
    Attempting { attempt_id: u64, revoked: bool },
    Retained,
    Orphaned,
    Opened,
}

pub struct PreparedWorkspaceReservation {
    pub(super) window: String,
    generation: u64,
    request: String,
    workspace_id: WorkspaceId,
    expected_version: u64,
    expires_at: Instant,
}

/// Native-only values required by the later host-side runtime mutation.
#[allow(dead_code)] // Task 8 consumes this host-only prepared workspace.
pub struct PreparedWorkspace {
    root: VerifiedRootHandle,
    admission: ProtectedRootHandleAdmission,
    workspace_id: WorkspaceId,
    expected_version: u64,
    operation_permit: Option<tokio::sync::OwnedMutexGuard<()>>,
}

#[allow(dead_code)] // Task 8 is the only native prepared-workspace consumer.
impl PreparedWorkspace {
    #[must_use]
    pub const fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    #[must_use]
    pub const fn expected_version(&self) -> u64 {
        self.expected_version
    }

    #[must_use]
    pub fn into_native_parts(
        self,
    ) -> (
        VerifiedRootHandle,
        ProtectedRootHandleAdmission,
        Option<tokio::sync::OwnedMutexGuard<()>>,
    ) {
        (self.root, self.admission, self.operation_permit)
    }
}

impl fmt::Debug for PreparedWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedWorkspace(<native-only>)")
    }
}

/// Host-only manager sharing the renderer-generation lock with selections.
pub struct PreparedWorkspaceManager {
    state: SharedSelectionState,
}

/// Drop-cleaned reservation that owns no root or daemon admission.
pub struct PreparedWorkspaceReservationGuard {
    manager: PreparedWorkspaceManager,
    reference: Option<PreparedWorkspaceRef>,
}

impl PreparedWorkspaceReservationGuard {
    pub(crate) const fn reference(&self) -> &PreparedWorkspaceRef {
        self.reference.as_ref().expect("reservation remains armed")
    }

    pub(crate) fn disarm(mut self) -> PreparedWorkspaceRef {
        self.reference.take().expect("reservation remains armed")
    }
}

impl Drop for PreparedWorkspaceReservationGuard {
    fn drop(&mut self) {
        if let Some(reference) = &self.reference {
            self.manager.cancel(reference);
        }
    }
}

/// Exact renderer and Workspace binding for one prepared native root.
pub struct PreparedWorkspaceBinding {
    window: String,
    generation: u64,
    request: String,
    workspace_id: WorkspaceId,
    expected_version: u64,
}

impl PreparedWorkspaceBinding {
    /// Creates a bounded exact binding.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid host bindings or a zero Workspace version.
    pub fn new(
        window: &str,
        generation: u64,
        request: &str,
        workspace_id: WorkspaceId,
        expected_version: u64,
    ) -> Result<Self, SelectionError> {
        if !valid_binding(window) || !valid_binding(request) || expected_version == 0 {
            return Err(SelectionError);
        }
        Ok(Self {
            window: window.to_owned(),
            generation,
            request: request.to_owned(),
            workspace_id,
            expected_version,
        })
    }
}

impl PreparedWorkspaceManager {
    pub(super) const fn from_shared_state(state: SharedSelectionState) -> Self {
        Self { state }
    }

    /// Consumes one exact prepared root for a later native mutation.
    ///
    /// # Errors
    ///
    /// Returns a closed error for expired, stale, mismatched, or replayed references.
    #[allow(dead_code)] // Task 8 is the only host-side consumer.
    pub fn consume(
        &self,
        reference: &PreparedWorkspaceRef,
        window: &str,
        expected_generation: u64,
        request: &str,
        now: Instant,
    ) -> Result<PreparedWorkspace, SelectionError> {
        if !valid_binding(window) || !valid_binding(request) {
            return Err(SelectionError);
        }
        let mut state = self.state.lock().map_err(|_| SelectionError)?;
        let generation = state
            .existing_generation(window)
            .map_err(|_| SelectionError)?;
        let entry = state.prepared.get(&reference.0).ok_or(SelectionError)?;
        if entry.expires_at <= now {
            state.prepared.remove(&reference.0);
            return Err(SelectionError);
        }
        if generation != expected_generation
            || entry.window != window
            || entry.generation != generation
            || entry.request != request
        {
            return Err(SelectionError);
        }
        let entry = state.prepared.remove(&reference.0).ok_or(SelectionError)?;
        drop(state);
        Ok(PreparedWorkspace {
            root: entry.root.ok_or(SelectionError)?,
            admission: entry.admission.ok_or(SelectionError)?,
            workspace_id: entry.workspace_id,
            expected_version: entry.expected_version,
            operation_permit: entry.operation_permit,
        })
    }
}

impl Clone for PreparedWorkspaceManager {
    fn clone(&self) -> Self {
        Self::from_shared_state(Arc::clone(&self.state))
    }
}

impl fmt::Debug for PreparedWorkspaceManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PreparedWorkspaceManager(<native-only>)")
    }
}

include!("prepared_workspace_parts/reservations.rs");
include!("prepared_workspace_parts/expiry.rs");
include!("prepared_workspace_parts/composite.rs");
include!("prepared_workspace_parts/open_attempt.rs");
#[cfg(all(test, feature = "test-support"))]
include!("prepared_workspace_parts/test_support.rs");
