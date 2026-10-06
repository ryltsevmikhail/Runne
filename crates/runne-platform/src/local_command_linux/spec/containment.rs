use super::*;
use runne_application::permission_modes::{
    CompositeEffectScope, ContainmentStrategy, NativeScopeAdmissionReceipt,
};
use std::os::fd::OwnedFd;

/// Validated scope and app receipt paired with one platform-owned registry.
#[derive(Clone, Copy)]
pub enum LinuxCommandContainmentV1<'a> {
    /// Workspace Landlock with an explicit network-none scope.
    WorkspaceBoundV1 {
        /// Exact frozen invocation scope admitted by the runtime.
        scope: &'a CompositeEffectScope,
        /// App-issued opaque native scope handle bound to `scope`.
        receipt: NativeScopeAdmissionReceipt,
        /// Executor-owned registry retaining protected roots and one-shot state.
        admission: &'a super::super::composite_admission::LinuxCompositeScopeAdmission,
    },
    /// Broad or explicit no-network same-user containment in the gated executor.
    SameUserCompositeV1 {
        /// Exact frozen invocation scope admitted by the runtime.
        scope: &'a CompositeEffectScope,
        /// App-issued opaque native scope handle bound to `scope`.
        receipt: NativeScopeAdmissionReceipt,
        /// Executor-owned registry retaining protected roots and one-shot state.
        admission: &'a super::super::composite_admission::LinuxCompositeScopeAdmission,
    },
}

impl LinuxCommandSpec<'_> {
    /// Checks the exact typed scope receipt and native prerequisites without forking.
    pub fn preflight_with_containment(
        &self,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<(), LinuxCommandError> {
        let (scope, receipt, admission, expected) = parts(containment);
        if scope.containment != expected {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        if expected == ContainmentStrategy::WorkspaceBoundV1 {
            self.preflight()?;
        } else {
            if !self.executable.is_sealed_snapshot() {
                return Err(LinuxCommandError::CompositePolicyUnenforceable);
            }
            let _ = encode_vectors(&self.argv, &self.env)?;
            self.executable.validate_provenance()?;
            policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
        }
        admission.inspect(scope, receipt, self.workspace, self.cwd, false)?;
        Ok(())
    }

    /// Starts a gated child under the typed scope and its one-shot native receipt.
    pub fn spawn_gated_with_containment<'a>(
        &self,
        area: &'a LinuxManagedArea,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        self.spawn_with_containment(area, CommandStdio::discard()?, containment)
    }

    /// Starts the same gated child with bounded stdio and typed scope enforcement.
    pub fn spawn_gated_with_containment_with_io<'a>(
        &self,
        area: &'a LinuxManagedArea,
        input: &[u8],
        limits: LinuxCommandOutputLimitsV1,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        self.spawn_with_containment(area, CommandStdio::bounded(input, limits)?, containment)
    }

    fn spawn_with_containment<'a>(
        &self,
        area: &'a LinuxManagedArea,
        stdio: CommandStdio,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        let (scope, receipt, admission, expected) = parts(containment);
        if scope.containment != expected {
            return Err(LinuxCommandError::CompositePolicyUnenforceable);
        }
        if area.is_populated().map_err(|_| LinuxCommandError::Area)? {
            return Err(LinuxCommandError::Area);
        }
        let (argv, env) = encode_vectors(&self.argv, &self.env)?;
        self.executable.validate_provenance()?;
        policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
        let ruleset: Option<OwnedFd> = match expected {
            ContainmentStrategy::WorkspaceBoundV1 => {
                Some(policy::build_ruleset(self.workspace, &self.executable)?)
            }
            ContainmentStrategy::SameUserCompositeV1 => {
                if !self.executable.is_sealed_snapshot() {
                    return Err(LinuxCommandError::CompositePolicyUnenforceable);
                }
                None
            }
        };
        let (prepared, network_none) =
            admission.inspect(scope, receipt, self.workspace, self.cwd, true)?;
        child::spawn(child::SpawnSpec {
            exe: self.executable.file(),
            workspace: self.workspace,
            cwd: self.cwd,
            ruleset: ruleset.as_ref(),
            argv: &argv,
            env: &env,
            area,
            stdio,
            composite: prepared.as_ref(),
            network_none,
        })
    }
}

fn parts(
    strategy: LinuxCommandContainmentV1<'_>,
) -> (
    &CompositeEffectScope,
    NativeScopeAdmissionReceipt,
    &super::super::composite_admission::LinuxCompositeScopeAdmission,
    ContainmentStrategy,
) {
    match strategy {
        LinuxCommandContainmentV1::WorkspaceBoundV1 {
            scope,
            receipt,
            admission,
        } => (
            scope,
            receipt,
            admission,
            ContainmentStrategy::WorkspaceBoundV1,
        ),
        LinuxCommandContainmentV1::SameUserCompositeV1 {
            scope,
            receipt,
            admission,
        } => (
            scope,
            receipt,
            admission,
            ContainmentStrategy::SameUserCompositeV1,
        ),
    }
}
