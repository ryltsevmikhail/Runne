//! Native macOS permission owner over held paths and a sealed executable.
//!
//! The owner records the same closed facts as the Linux adapter, but proves
//! them with a held-descriptor `fstat` identity instead of `openat2` and
//! `/proc`. Preparation never spawns: it only fixes the bytes and descriptors
//! that a later release step must re-verify.
//!
//! It does not rediscover the workspace. It trusts the descriptors the broker
//! already opened and only fixes their identity, so containment still depends
//! on the caller holding the admitted root, exactly as the Linux owner relies
//! on `openat2` beneath it.
#![allow(unsafe_code)]

use super::error::MacOsCommandError as CommandError;
use super::sealed::SealedExecutableSnapshot;
use crate::local_command_digest::{self as digest, DigestError};
use runne_domain::task_run::TaskRunLocalCommand;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::Arc;

const OWNER_GENERATION: u64 = 1;

/// Native owner identity for one macOS execution node.
///
/// A fresh owner has a random identifier and generation `1`; rebuilding an
/// owner yields a new identity rather than a higher generation. The generation
/// field exists so stored facts keep the same shape on every platform.
pub struct MacOsPermissionOwnerV1 {
    state: Arc<OwnerState>,
}

/// Restricted target-preparation view paired with one native owner.
///
/// The view keeps the owner state alive: a preparation cannot outlive the
/// identity it was issued under.
#[derive(Clone)]
pub struct MacOsPermissionPreparationV1 {
    state: Arc<OwnerState>,
}

struct OwnerState {
    owner_id: [u8; 16],
    generation: u64,
}

/// Read-only target observations; these fields alone cannot spawn or release a child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PermissionTargetObservationV1 {
    pub(super) owner_id: [u8; 16],
    pub(super) owner_generation: u64,
    pub(super) target_identity: [u8; 32],
    pub(super) target_version: u64,
    pub(super) workspace_identity: [u8; 32],
    pub(super) cwd_identity: [u8; 32],
    pub(super) executable_digest: [u8; 32],
    pub(super) environment_digest: [u8; 32],
    pub(super) normalized_arguments_digest: [u8; 32],
    pub(super) schema_digest: [u8; 32],
}

/// Held descriptors and sealed bytes fixed by one preparation.
pub struct PreparedMacOsPermissionTargetV1 {
    command: TaskRunLocalCommand,
    workspace: File,
    cwd: File,
    snapshot: SealedExecutableSnapshot,
    observation: PermissionTargetObservationV1,
}

impl MacOsPermissionOwnerV1 {
    /// Creates a fresh owner with a random non-secret identity.
    ///
    /// # Errors
    /// Returns unavailable when the system entropy source fails.
    pub fn new() -> Result<Arc<Self>, CommandError> {
        let mut owner_id = [0_u8; 16];
        if unsafe { libc::getentropy(owner_id.as_mut_ptr().cast(), owner_id.len()) } != 0 {
            return Err(CommandError::Unavailable);
        }
        Ok(Arc::new(Self {
            state: Arc::new(OwnerState {
                owner_id,
                generation: OWNER_GENERATION,
            }),
        }))
    }

    /// Returns a preparation-only view. It has no release method or child token.
    pub fn preparation(&self) -> MacOsPermissionPreparationV1 {
        MacOsPermissionPreparationV1 {
            state: Arc::clone(&self.state),
        }
    }
}

impl MacOsPermissionPreparationV1 {
    /// Prepares exactly the structured command and held descriptors supplied by the broker.
    ///
    /// # Errors
    /// Returns invalid for an unusable descriptor set, unverified when the
    /// sealed image no longer proves its bytes, and unavailable when a
    /// descriptor cannot be cloned.
    pub fn prepare_target(
        &self,
        command: TaskRunLocalCommand,
        workspace: &File,
        cwd: &File,
        snapshot: SealedExecutableSnapshot,
    ) -> Result<PreparedMacOsPermissionTargetV1, CommandError> {
        if self.state.generation == 0 {
            return Err(CommandError::Unverified);
        }
        snapshot.validate_seals()?;
        let workspace = workspace
            .try_clone()
            .map_err(|_| CommandError::Unavailable)?;
        let cwd = cwd.try_clone().map_err(|_| CommandError::Unavailable)?;
        if !is_directory(&workspace)? || !is_directory(&cwd)? {
            return Err(CommandError::Invalid);
        }
        let (object_id, generation) = snapshot.permission_identity();
        let workspace_identity = digest::descriptor_identity(&workspace).map_err(into_error)?;
        let cwd_identity = digest::descriptor_identity(&cwd).map_err(into_error)?;
        let executable_digest = digest::file_digest(snapshot.file()).map_err(into_error)?;
        let environment_digest = digest::environment_digest(&command).map_err(into_error)?;
        let observation = PermissionTargetObservationV1 {
            owner_id: self.state.owner_id,
            owner_generation: self.state.generation,
            target_identity: digest::target_identity(
                object_id,
                generation,
                workspace_identity,
                cwd_identity,
                executable_digest,
            ),
            target_version: generation,
            workspace_identity,
            cwd_identity,
            executable_digest,
            environment_digest,
            normalized_arguments_digest: command.intent_digest(),
            schema_digest: digest::schema_digest(),
        };
        Ok(PreparedMacOsPermissionTargetV1 {
            command,
            workspace,
            cwd,
            snapshot,
            observation,
        })
    }
}

impl PreparedMacOsPermissionTargetV1 {
    /// Facts a caller may persist, compare or refuse.
    #[must_use]
    pub const fn observation(&self) -> PermissionTargetObservationV1 {
        self.observation
    }

    /// Structured command admitted for this target.
    #[must_use]
    pub const fn command(&self) -> &TaskRunLocalCommand {
        &self.command
    }

    /// Held workspace descriptor.
    #[must_use]
    pub const fn workspace(&self) -> &File {
        &self.workspace
    }

    /// Held working-directory descriptor.
    #[must_use]
    pub const fn cwd(&self) -> &File {
        &self.cwd
    }

    /// Sealed executable image bound to this target.
    #[must_use]
    pub const fn snapshot(&self) -> &SealedExecutableSnapshot {
        &self.snapshot
    }

    /// Re-proves the held descriptors and sealed bytes against the observation.
    ///
    /// # Errors
    /// Returns unverified when any bound fact changed after preparation.
    pub fn verify_held(&self) -> Result<(), CommandError> {
        self.snapshot.validate_seals()?;
        let workspace = digest::descriptor_identity(&self.workspace).map_err(into_error)?;
        let cwd = digest::descriptor_identity(&self.cwd).map_err(into_error)?;
        let executable = digest::file_digest(self.snapshot.file()).map_err(into_error)?;
        if workspace != self.observation.workspace_identity
            || cwd != self.observation.cwd_identity
            || executable != self.observation.executable_digest
        {
            return Err(CommandError::Unverified);
        }
        Ok(())
    }
}

impl PermissionTargetObservationV1 {
    /// Returns the digest of the retained executable target identity.
    #[must_use]
    pub const fn target_identity(&self) -> &[u8; 32] {
        &self.target_identity
    }

    /// Returns the sealed target generation used in that identity.
    #[must_use]
    pub const fn target_version(&self) -> u64 {
        self.target_version
    }

    /// Returns the registered native owner identifier as data only.
    #[must_use]
    pub const fn owner_id(&self) -> &[u8; 16] {
        &self.owner_id
    }

    /// Returns the registered native owner generation as data only.
    #[must_use]
    pub const fn owner_generation(&self) -> u64 {
        self.owner_generation
    }

    /// Returns the held workspace descriptor identity digest.
    #[must_use]
    pub const fn workspace_identity(&self) -> &[u8; 32] {
        &self.workspace_identity
    }

    /// Returns the held working-directory descriptor identity digest.
    #[must_use]
    pub const fn cwd_identity(&self) -> &[u8; 32] {
        &self.cwd_identity
    }

    /// Returns the sealed executable bytes digest.
    #[must_use]
    pub const fn executable_digest(&self) -> &[u8; 32] {
        &self.executable_digest
    }

    /// Returns the normalized command environment digest.
    #[must_use]
    pub const fn environment_digest(&self) -> &[u8; 32] {
        &self.environment_digest
    }

    /// Returns the normalized structured-arguments digest.
    #[must_use]
    pub const fn normalized_arguments_digest(&self) -> &[u8; 32] {
        &self.normalized_arguments_digest
    }

    /// Returns the closed command schema digest.
    #[must_use]
    pub const fn schema_digest(&self) -> &[u8; 32] {
        &self.schema_digest
    }
}

fn is_directory(file: &File) -> Result<bool, CommandError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(CommandError::Unavailable);
    }
    Ok(stat.st_mode & libc::S_IFMT == libc::S_IFDIR)
}

const fn into_error(error: DigestError) -> CommandError {
    match error {
        DigestError::Invalid => CommandError::Invalid,
        DigestError::Unavailable => CommandError::Unavailable,
    }
}

#[cfg(test)]
#[path = "permission_tests.rs"]
mod tests;
