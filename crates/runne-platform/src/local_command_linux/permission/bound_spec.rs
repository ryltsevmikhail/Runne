use super::super::{
    LinuxCommandContainmentV1, LinuxCommandContainmentV2, LinuxCommandError,
    LinuxCommandExecutable, LinuxCommandOutputLimitsV1, LinuxCommandSpec,
    LinuxCompositeScopeAdmission, snapshot::SealedExecutableSnapshot,
};
use super::{child::PermissionChildV1, lineage::PermissionTargetObservationV1};
use crate::process_managed_area::LinuxManagedArea;
use runne_application::permission_modes::{
    ContainmentStrategy, LocalCommandPermissionBindingV1, NativeScopeAdmissionReceipt,
};
use std::ffi::OsString;
use std::fs::File;
use std::sync::Arc;

/// Owned actual command target, held descriptors and sealed bytes awaiting Store capture.
pub struct PreparedPermissionTargetV1 {
    pub(super) command: runne_domain::task_run::TaskRunLocalCommand,
    pub(super) workspace: File,
    pub(super) cwd: File,
    pub(super) snapshot: SealedExecutableSnapshot,
    pub(super) observation: PermissionTargetObservationV1,
    pub(super) admission: Arc<LinuxCompositeScopeAdmission>,
}

/// Bound native spec created only after Store returned the exact original binding.
pub struct BoundPermissionSpecV1 {
    original: LocalCommandPermissionBindingV1,
    observation: PermissionTargetObservationV1,
    command: runne_domain::task_run::TaskRunLocalCommand,
    workspace: File,
    cwd: File,
    snapshot: SealedExecutableSnapshot,
    admission: Arc<LinuxCompositeScopeAdmission>,
}

impl PreparedPermissionTargetV1 {
    /// Returns data-only observations from this exact owned target.
    pub const fn observation(&self) -> PermissionTargetObservationV1 {
        self.observation
    }

    /// Binds only if every native target field equals the captured original approval.
    pub fn bind(
        self,
        original: LocalCommandPermissionBindingV1,
    ) -> Result<BoundPermissionSpecV1, LinuxCommandError> {
        let approval = original.approval();
        let expected_executable = self.observation.executable_digest;
        if original.command() != &self.command
            || approval.normalized_arguments_digest.as_bytes()
                != &self.observation.normalized_arguments_digest
            || approval.tool_schema_digest.as_bytes() != &self.observation.schema_digest
            || approval.target_identity_digest.as_bytes() != &self.observation.target_identity
            || approval.target_version != self.observation.target_version
            || approval.environment_digest.as_bytes() != &self.observation.environment_digest
            || approval.cwd_identity_digest.as_bytes() != &self.observation.cwd_identity
            || approval.executable_digest.map(|digest| *digest.as_bytes())
                != Some(expected_executable)
            || approval.containment_version != original.scope().containment
        {
            return Err(LinuxCommandError::Unverified);
        }
        Ok(BoundPermissionSpecV1 {
            original,
            observation: self.observation,
            command: self.command,
            workspace: self.workspace,
            cwd: self.cwd,
            snapshot: self.snapshot,
            admission: self.admission,
        })
    }
}

impl BoundPermissionSpecV1 {
    /// Borrowed immutable original approval; it carries no release authority.
    pub(super) const fn original(&self) -> &LocalCommandPermissionBindingV1 {
        &self.original
    }

    pub(super) const fn observation(&self) -> PermissionTargetObservationV1 {
        self.observation
    }

    /// Creates the existing gated child, still held before the one-shot GO boundary.
    pub fn spawn<'a>(
        self,
        area: &'a LinuxManagedArea,
        receipt: NativeScopeAdmissionReceipt,
        input: &[u8],
    ) -> Result<PermissionChildV1<'a>, LinuxCommandError> {
        if input.len() > 16 * 1024 {
            return Err(LinuxCommandError::Invalid);
        }
        let limits = self.original.limits();
        let output = LinuxCommandOutputLimitsV1::new(
            limits
                .stdout_capture_bytes_usize()
                .map_err(|_| LinuxCommandError::Invalid)?,
            limits
                .stderr_capture_bytes_usize()
                .map_err(|_| LinuxCommandError::Invalid)?,
        )?;
        let argv = self.command.argv().iter().map(OsString::from).collect();
        let env = self
            .command
            .env()
            .iter()
            .map(|(k, v)| (OsString::from(k), OsString::from(v)))
            .collect();
        let spec = LinuxCommandSpec {
            executable: LinuxCommandExecutable::SealedSnapshot(&self.snapshot),
            workspace: &self.workspace,
            cwd: &self.cwd,
            argv,
            env,
        };
        let scope = self.original.scope();
        if receipt.scope_digest() != scope.digest().map_err(|_| LinuxCommandError::Unverified)?
            || receipt.managed_policy_digest() != scope.managed_policy.policy_digest()
            || receipt.containment() != scope.containment
        {
            return Err(LinuxCommandError::Unverified);
        }
        let child = match scope.containment {
            ContainmentStrategy::WorkspaceBoundV1 => spec.spawn_gated_with_containment_with_io(
                area,
                input,
                output,
                LinuxCommandContainmentV1::WorkspaceBoundV1 {
                    scope,
                    receipt,
                    admission: &self.admission,
                },
            ),
            ContainmentStrategy::SameUserCompositeV1 => spec.spawn_gated_with_containment_with_io(
                area,
                input,
                output,
                LinuxCommandContainmentV1::SameUserCompositeV1 {
                    scope,
                    receipt,
                    admission: &self.admission,
                },
            ),
            ContainmentStrategy::SameUserCompositeV2 => spec
                .spawn_gated_with_containment_v2_with_io(
                    area,
                    input,
                    output,
                    LinuxCommandContainmentV2::SameUserCompositeV2 {
                        scope,
                        receipt,
                        admission: &self.admission,
                    },
                ),
        }?;
        Ok(PermissionChildV1::new(child, area, self, receipt))
    }
}
