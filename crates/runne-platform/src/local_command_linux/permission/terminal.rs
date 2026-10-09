use super::super::{
    LinuxCommandError, LinuxCommandOutputChunkV1, LinuxCompositeScopeAdmission,
    LinuxLeaderExitKindV1, LinuxLeaderExitObservationV1, child::composite::PreparedComposite,
    spec::GatedLinuxChild,
};
use super::child::PermissionChildV1;
use super::{helper::PermissionHelperObservationV1, helper_protocol};
use crate::process_managed_area::{LinuxManagedArea, VerifiedEmptyManagedArea};
use runne_application::permission_modes::{CompositeEffectScope, NativeScopeAdmissionReceipt};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

/// Borrowed terminal evidence tied to one actual waited child and empty area.
pub struct PermissionChildTerminalEvidenceV1<'child, 'area> {
    pub(super) child: &'child PermissionChildV1<'area>,
    pub(super) empty: VerifiedEmptyManagedArea<'area>,
    pub(super) exit_kind: LinuxLeaderExitKindV1,
}

impl PermissionChildTerminalEvidenceV1<'_, '_> {
    /// Returns the classified waitpid result for the borrowed actual child.
    pub const fn leader_exit_kind(&self) -> LinuxLeaderExitKindV1 {
        self.exit_kind
    }

    /// Returns read-only target data borrowed from the same child lineage.
    pub const fn observation(&self) -> super::lineage::PermissionTargetObservationV1 {
        self.child.observation()
    }

    /// Confirms bounded output bytes and lifecycle facts came from this child.
    #[expect(
        clippy::too_many_arguments,
        reason = "The terminal receipt matches exact stdout/stderr bytes and their observed, truncation, EOF, and overflow facts."
    )]
    pub fn output_matches(
        &self,
        stdout: &[u8],
        stderr: &[u8],
        stdout_observed: i64,
        stderr_observed: i64,
        stdout_truncated: bool,
        stderr_truncated: bool,
        stdout_eof: bool,
        stderr_eof: bool,
        overflowed: bool,
    ) -> bool {
        self.child.stdout == stdout
            && self.child.stderr == stderr
            && i64::try_from(self.child.stdout_observed).ok() == Some(stdout_observed)
            && i64::try_from(self.child.stderr_observed).ok() == Some(stderr_observed)
            && self.child.stdout_truncated == stdout_truncated
            && self.child.stderr_truncated == stderr_truncated
            && self.child.stdout_eof == stdout_eof
            && self.child.stderr_eof == stderr_eof
            && self.child.output_overflowed == overflowed
    }

    /// Returns the verified empty-area identity bytes.
    pub fn area_identity(&self) -> &[u8; 100] {
        self.empty.identity_bytes()
    }

    /// Revalidates that the same managed process area remains empty.
    pub fn revalidate_empty_area(&self) -> Result<(), LinuxCommandError> {
        self.empty.revalidate().map_err(Into::into)
    }
}

/// Opaque helper child bound to the same consumed registry entry, target and area.
pub struct PermissionHelperChildV1<'area> {
    pub(super) child: GatedLinuxChild<'area>,
    pub(super) area: &'area LinuxManagedArea,
    pub(super) admission: Arc<LinuxCompositeScopeAdmission>,
    pub(super) scope: CompositeEffectScope,
    pub(super) receipt: NativeScopeAdmissionReceipt,
    pub(super) request: Vec<u8>,
    pub(super) parsed: helper_protocol::ParsedHelperRequest,
    pub(super) workspace: std::fs::File,
    pub(super) cwd: std::fs::File,
    pub(super) prepared: PreparedComposite,
    pub(super) admitted_at: Instant,
    pub(super) owner_id: [u8; 16],
    pub(super) generation: u64,
    pub(super) area_identity: [u8; 100],
}

impl<'area> PermissionHelperChildV1<'area> {
    /// Polls the helper and drains available bounded output.
    pub fn poll_output(&mut self) -> Result<(), LinuxCommandError> {
        self.child.poll_output()
    }

    /// Takes the next buffered output chunk from the helper.
    pub fn take_output(&mut self) -> LinuxCommandOutputChunkV1 {
        self.child.take_output()
    }

    /// Returns the typed leader exit if it has completed.
    pub fn try_wait(&mut self) -> Result<Option<LinuxLeaderExitKindV1>, LinuxCommandError> {
        match self.child.try_wait()? {
            None => Ok(None),
            Some(_) => self
                .child
                .leader_exit_observation()
                .map(LinuxLeaderExitObservationV1::kind)
                .map(Some)
                .ok_or(LinuxCommandError::Unverified),
        }
    }

    /// Waits for the helper leader to exit within the supplied timeout.
    pub fn wait_leader(
        &mut self,
        timeout: Duration,
    ) -> Result<LinuxLeaderExitKindV1, LinuxCommandError> {
        if timeout > Duration::from_secs(3600) {
            return Err(LinuxCommandError::Invalid);
        }
        let deadline = Instant::now() + timeout;
        loop {
            self.poll_output()?;
            if let Some(exit) = self.try_wait()? {
                return Ok(exit);
            }
            if Instant::now() >= deadline {
                return Err(LinuxCommandError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Requests termination of the helper's managed process area.
    pub fn terminate_area(&self, grace: Duration) -> Result<(), LinuxCommandError> {
        self.child.terminate_area(grace)
    }

    /// Reaps the helper leader after a stop request.
    pub fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), LinuxCommandError> {
        self.child.reap_after_stop(timeout)
    }

    /// Reports whether the registered owner released this helper child.
    pub const fn was_released(&self) -> bool {
        self.child.was_released()
    }

    /// Returns facts parsed from the exact request retained for this child.
    pub fn observation(&self) -> &PermissionHelperObservationV1 {
        &self.parsed.observation
    }

    /// Returns the native receipt consumed to create this child.
    pub const fn native_receipt(&self) -> NativeScopeAdmissionReceipt {
        self.receipt
    }

    /// Proves the leader was waited and the managed process area is empty.
    pub fn terminal_evidence(
        &self,
    ) -> Result<PermissionHelperTerminalEvidenceV1<'_, 'area>, LinuxCommandError> {
        let exit = self
            .child
            .leader_exit_observation()
            .ok_or(LinuxCommandError::Unverified)?;
        let empty = self.area.prove_empty().map_err(LinuxCommandError::from)?;
        Ok(PermissionHelperTerminalEvidenceV1 {
            child: self,
            empty,
            exit_kind: exit.kind(),
        })
    }
}

/// Borrowed terminal facts for one waited helper and its verified empty area.
pub struct PermissionHelperTerminalEvidenceV1<'child, 'area> {
    child: &'child PermissionHelperChildV1<'area>,
    empty: VerifiedEmptyManagedArea<'area>,
    exit_kind: LinuxLeaderExitKindV1,
}

impl PermissionHelperTerminalEvidenceV1<'_, '_> {
    /// Returns the classified wait result for the helper leader.
    pub const fn leader_exit_kind(&self) -> LinuxLeaderExitKindV1 {
        self.exit_kind
    }

    /// Returns the parsed request facts for the completed helper.
    pub fn observation(&self) -> &PermissionHelperObservationV1 {
        &self.child.parsed.observation
    }

    /// Returns the identity bytes of the verified empty process area.
    pub fn area_identity(&self) -> &[u8; 100] {
        self.empty.identity_bytes()
    }

    /// Rechecks that the same managed process area remains empty.
    pub fn revalidate_empty_area(&self) -> Result<(), LinuxCommandError> {
        self.empty.revalidate().map_err(Into::into)
    }
}
