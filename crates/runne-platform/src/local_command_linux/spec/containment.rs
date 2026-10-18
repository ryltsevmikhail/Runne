use super::*;
use runne_application::permission_modes::{
    CompositeEffectScope, ContainmentStrategy, NativeScopeAdmissionReceipt,
};
use std::os::fd::OwnedFd;

/// Typed scope wrappers for the frozen V1 containment profiles.
#[derive(Clone, Copy)]
pub enum LinuxCommandContainmentV1<'a> {
    /// Workspace Landlock with an explicit network-none scope.
    WorkspaceBoundV1 {
        /// Exact scope being released.
        scope: &'a CompositeEffectScope,
        /// One-shot native receipt admitted for the exact scope.
        receipt: NativeScopeAdmissionReceipt,
        /// Runtime-owned registry holding protected roots and admission state.
        admission: &'a super::super::composite_admission::LinuxCompositeScopeAdmission,
    },
    /// Legacy broad same-user namespace containment.
    SameUserCompositeV1 {
        /// Exact scope being released.
        scope: &'a CompositeEffectScope,
        /// One-shot native receipt admitted for the exact scope.
        receipt: NativeScopeAdmissionReceipt,
        /// Runtime-owned registry holding protected roots and admission state.
        admission: &'a super::super::composite_admission::LinuxCompositeScopeAdmission,
    },
}

/// Typed wrapper for the Landlock ABI 3 same-user partial-rights profile.
#[derive(Clone, Copy)]
pub enum LinuxCommandContainmentV2<'a> {
    /// Broad same-user scope with exact filesystem rights and V2 protected roots.
    SameUserCompositeV2 {
        /// Exact partial-rights scope being released.
        scope: &'a CompositeEffectScope,
        /// One-shot native receipt admitted for the exact scope.
        receipt: NativeScopeAdmissionReceipt,
        /// Runtime-owned registry holding protected roots and admission state.
        admission: &'a super::super::composite_admission::LinuxCompositeScopeAdmission,
    },
}

#[derive(Clone, Copy)]
struct Profile<'a> {
    scope: &'a CompositeEffectScope,
    receipt: NativeScopeAdmissionReceipt,
    admission: &'a super::super::composite_admission::LinuxCompositeScopeAdmission,
    expected: ContainmentStrategy,
}

impl LinuxCommandSpec<'_> {
    /// Checks the exact typed V1 scope and native prerequisites without forking.
    pub fn preflight_with_containment(
        &self,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<(), LinuxCommandError> {
        self.preflight_profile(parts_v1(containment))
    }

    /// Checks the exact typed V2 scope and Landlock profile without forking.
    pub fn preflight_with_containment_v2(
        &self,
        containment: LinuxCommandContainmentV2<'_>,
    ) -> Result<(), LinuxCommandError> {
        self.preflight_profile(parts_v2(containment))
    }

    /// Starts the V1 gated child under its one-shot native receipt.
    pub fn spawn_gated_with_containment<'a>(
        &self,
        area: &'a LinuxManagedArea,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        self.spawn_profile(area, CommandStdio::discard()?, parts_v1(containment))
    }

    /// Starts a V1 child with bounded stdio and typed scope enforcement.
    pub fn spawn_gated_with_containment_with_io<'a>(
        &self,
        area: &'a LinuxManagedArea,
        input: &[u8],
        limits: LinuxCommandOutputLimitsV1,
        containment: LinuxCommandContainmentV1<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        self.spawn_profile(
            area,
            CommandStdio::bounded(input, limits)?,
            parts_v1(containment),
        )
    }

    /// Starts a V2 child under exact Landlock ABI 3 filesystem rights.
    pub fn spawn_gated_with_containment_v2<'a>(
        &self,
        area: &'a LinuxManagedArea,
        containment: LinuxCommandContainmentV2<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        self.spawn_profile(area, CommandStdio::discard()?, parts_v2(containment))
    }

    /// Starts a V2 child with bounded stdio and exact partial-rights enforcement.
    pub fn spawn_gated_with_containment_v2_with_io<'a>(
        &self,
        area: &'a LinuxManagedArea,
        input: &[u8],
        limits: LinuxCommandOutputLimitsV1,
        containment: LinuxCommandContainmentV2<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        self.spawn_profile(
            area,
            CommandStdio::bounded(input, limits)?,
            parts_v2(containment),
        )
    }

    fn preflight_profile(&self, profile: Profile<'_>) -> Result<(), LinuxCommandError> {
        validate_profile_scope(profile)?;
        if profile.expected == ContainmentStrategy::WorkspaceBoundV1 {
            self.preflight()?;
        } else {
            if !self.executable.is_sealed_snapshot() {
                return Err(LinuxCommandError::CompositePolicyUnenforceable);
            }
            let _ = encode_vectors(&self.argv, &self.env)?;
            self.executable.validate_provenance()?;
            policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
            if profile.expected == ContainmentStrategy::SameUserCompositeV2 {
                let rights = policy::native_fs_profile(&profile.scope.filesystem.permissions)?;
                drop(policy::build_composite_ruleset(rights, &self.executable)?);
            }
        }
        profile.admission.inspect(
            profile.scope,
            profile.receipt,
            self.workspace,
            self.cwd,
            false,
        )?;
        Ok(())
    }

    fn spawn_profile<'a>(
        &self,
        area: &'a LinuxManagedArea,
        stdio: CommandStdio,
        profile: Profile<'_>,
    ) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
        validate_profile_scope(profile)?;
        if area.is_populated().map_err(|_| LinuxCommandError::Area)? {
            return Err(LinuxCommandError::Area);
        }
        let (argv, env) = encode_vectors(&self.argv, &self.env)?;
        self.executable.validate_provenance()?;
        policy::validate_descriptors(self.executable.file(), self.workspace, self.cwd)?;
        let filesystem_profile = if profile.expected == ContainmentStrategy::SameUserCompositeV2 {
            Some(policy::native_fs_profile(
                &profile.scope.filesystem.permissions,
            )?)
        } else {
            None
        };
        let ruleset: Option<OwnedFd> = match profile.expected {
            ContainmentStrategy::WorkspaceBoundV1 => {
                Some(policy::build_ruleset(self.workspace, &self.executable)?)
            }
            ContainmentStrategy::SameUserCompositeV1 => None,
            ContainmentStrategy::SameUserCompositeV2 => Some(policy::build_composite_ruleset(
                filesystem_profile.expect("V2 profile was prepared"),
                &self.executable,
            )?),
        };
        let (prepared, network_none) = profile.admission.inspect(
            profile.scope,
            profile.receipt,
            self.workspace,
            self.cwd,
            true,
        )?;
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
            filesystem_profile,
        })
    }
}

fn validate_profile_scope(profile: Profile<'_>) -> Result<(), LinuxCommandError> {
    if profile.scope.containment != profile.expected
        || (profile.scope.managed_policy.is_closed()
            && profile.expected == ContainmentStrategy::WorkspaceBoundV1)
    {
        return Err(LinuxCommandError::CompositePolicyUnenforceable);
    }
    Ok(())
}

fn parts_v1(containment: LinuxCommandContainmentV1<'_>) -> Profile<'_> {
    match containment {
        LinuxCommandContainmentV1::WorkspaceBoundV1 {
            scope,
            receipt,
            admission,
        } => Profile {
            scope,
            receipt,
            admission,
            expected: ContainmentStrategy::WorkspaceBoundV1,
        },
        LinuxCommandContainmentV1::SameUserCompositeV1 {
            scope,
            receipt,
            admission,
        } => Profile {
            scope,
            receipt,
            admission,
            expected: ContainmentStrategy::SameUserCompositeV1,
        },
    }
}

fn parts_v2(containment: LinuxCommandContainmentV2<'_>) -> Profile<'_> {
    match containment {
        LinuxCommandContainmentV2::SameUserCompositeV2 {
            scope,
            receipt,
            admission,
        } => Profile {
            scope,
            receipt,
            admission,
            expected: ContainmentStrategy::SameUserCompositeV2,
        },
    }
}
