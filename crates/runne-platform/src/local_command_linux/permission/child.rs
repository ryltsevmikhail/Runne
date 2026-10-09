use super::super::{
    LinuxCommandError, LinuxCommandOutputChunkV1, LinuxLeaderExitKindV1,
    LinuxLeaderExitObservationV1, spec::GatedLinuxChild,
};
use super::bound_spec::BoundPermissionSpecV1;
use super::{lineage::PermissionTargetObservationV1, terminal::PermissionChildTerminalEvidenceV1};
use crate::process_managed_area::LinuxManagedArea;
use runne_application::permission_modes::NativeScopeAdmissionReceipt;
use std::time::Duration;

/// Actual native child wrapper; its constructor and release fields stay private.
pub struct PermissionChildV1<'area> {
    pub(super) child: GatedLinuxChild<'area>,
    pub(super) area: &'area LinuxManagedArea,
    pub(super) bound: BoundPermissionSpecV1,
    receipt: NativeScopeAdmissionReceipt,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
    pub(super) stdout_observed: u64,
    pub(super) stderr_observed: u64,
    pub(super) stdout_truncated: bool,
    pub(super) stderr_truncated: bool,
    pub(super) stdout_eof: bool,
    pub(super) stderr_eof: bool,
    pub(super) output_overflowed: bool,
}

impl<'area> PermissionChildV1<'area> {
    pub(super) const fn new(
        child: GatedLinuxChild<'area>,
        area: &'area LinuxManagedArea,
        bound: BoundPermissionSpecV1,
        receipt: NativeScopeAdmissionReceipt,
    ) -> Self {
        Self {
            child,
            area,
            bound,
            receipt,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_observed: 0,
            stderr_observed: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            stdout_eof: false,
            stderr_eof: false,
            output_overflowed: false,
        }
    }

    /// Reports bounded nonblocking output readiness for the exact child.
    pub fn poll_output(&mut self) -> Result<(), LinuxCommandError> {
        self.child.poll_output()
    }

    /// Transfers only bytes retained under this invocation's immutable caps.
    pub fn take_output(&mut self) -> LinuxCommandOutputChunkV1 {
        let chunk = self.child.take_output();
        self.stdout.extend_from_slice(&chunk.stdout);
        self.stderr.extend_from_slice(&chunk.stderr);
        self.stdout_observed = chunk.stdout_observed_bytes;
        self.stderr_observed = chunk.stderr_observed_bytes;
        self.stdout_truncated |= chunk.stdout_truncated;
        self.stderr_truncated |= chunk.stderr_truncated;
        self.stdout_eof = chunk.stdout_eof;
        self.stderr_eof = chunk.stderr_eof;
        self.output_overflowed |= chunk.observed_bytes_overflowed;
        chunk
    }

    /// Polls the child wait cache and returns classified evidence, never a flattened status.
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

    /// Waits for the leader while preserving the same handle and bounded output drain.
    pub fn wait_leader(
        &mut self,
        timeout: Duration,
    ) -> Result<LinuxLeaderExitKindV1, LinuxCommandError> {
        if timeout > Duration::from_secs(3600) {
            return Err(LinuxCommandError::Invalid);
        }
        let deadline = std::time::Instant::now() + timeout;
        loop {
            self.poll_output()?;
            if let Some(outcome) = self.try_wait()? {
                return Ok(outcome);
            }
            if std::time::Instant::now() >= deadline {
                return Err(LinuxCommandError::Timeout);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Stops the exact complete area; callers separately reap the direct leader.
    pub fn terminate_area(&self, grace: Duration) -> Result<(), LinuxCommandError> {
        self.child.terminate_area(grace)
    }

    /// Reaps the owned leader only after the caller established area stop.
    pub fn reap_after_stop(&mut self, timeout: Duration) -> Result<(), LinuxCommandError> {
        self.child.reap_after_stop(timeout)
    }

    /// Read-only GO observation for Store reconciliation.
    pub const fn was_released(&self) -> bool {
        self.child.was_released()
    }

    /// Returns read-only target facts from this exact child lineage.
    pub const fn observation(&self) -> PermissionTargetObservationV1 {
        self.bound.observation()
    }

    /// Returns the identity of the already-created managed area without exposing its handle.
    pub fn area_identity(&self) -> [u8; 100] {
        self.area.identity().to_bytes()
    }

    /// Borrows the immutable original binding; it grants no spawn or release authority.
    pub const fn original_binding(
        &self,
    ) -> &runne_application::permission_modes::LocalCommandPermissionBindingV1 {
        self.bound.original()
    }

    pub(super) const fn receipt(&self) -> NativeScopeAdmissionReceipt {
        self.receipt
    }

    /// Proves actual leader waitpid evidence and recursive area emptiness together.
    pub fn terminal_evidence(
        &self,
    ) -> Result<PermissionChildTerminalEvidenceV1<'_, 'area>, LinuxCommandError> {
        let exit = self
            .child
            .leader_exit_observation()
            .ok_or(LinuxCommandError::Unverified)?;
        let empty = self.area.prove_empty().map_err(LinuxCommandError::from)?;
        Ok(PermissionChildTerminalEvidenceV1 {
            child: self,
            empty,
            exit_kind: exit.kind(),
        })
    }
}
