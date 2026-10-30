//! Linux composition of the shared structured-command digests.
//!
//! The byte encoding lives in [`crate::local_command_digest`] so macOS records
//! identical facts. This module only adds the sealed-snapshot proof and maps
//! failures onto the Linux command error.

use super::super::{LinuxCommandError, snapshot::SealedExecutableSnapshot};
use crate::local_command_digest::{self as shared, DigestError};
use runne_domain::task_run::TaskRunLocalCommand;
use std::fs::File;

pub(super) fn schema_digest() -> [u8; 32] {
    shared::schema_digest()
}

pub(super) fn environment_digest(
    command: &TaskRunLocalCommand,
) -> Result<[u8; 32], LinuxCommandError> {
    shared::environment_digest(command).map_err(into_command_error)
}

type TargetDigests = ([u8; 32], [u8; 32], [u8; 32], [u8; 32]);

pub(super) fn target_digest(
    snapshot: &SealedExecutableSnapshot,
    workspace: &File,
    cwd: &File,
) -> Result<TargetDigests, LinuxCommandError> {
    snapshot.validate_seals()?;
    let (object_id, generation) = snapshot.permission_identity();
    let workspace_id = shared::descriptor_identity(workspace).map_err(into_command_error)?;
    let cwd_id = shared::descriptor_identity(cwd).map_err(into_command_error)?;
    let executable = shared::file_digest(snapshot.file()).map_err(into_command_error)?;
    Ok((
        shared::target_identity(object_id, generation, workspace_id, cwd_id, executable),
        workspace_id,
        cwd_id,
        executable,
    ))
}

pub(super) fn target_identity(
    object_id: [u8; 16],
    generation: u64,
    workspace: [u8; 32],
    cwd: [u8; 32],
    executable: [u8; 32],
) -> [u8; 32] {
    shared::target_identity(object_id, generation, workspace, cwd, executable)
}

pub(super) fn descriptor_identity(file: &File) -> Result<[u8; 32], LinuxCommandError> {
    shared::descriptor_identity(file).map_err(into_command_error)
}

pub(super) fn file_digest(file: &File) -> Result<[u8; 32], LinuxCommandError> {
    shared::file_digest(file).map_err(into_command_error)
}

const fn into_command_error(error: DigestError) -> LinuxCommandError {
    match error {
        DigestError::Invalid => LinuxCommandError::Invalid,
        DigestError::Unavailable => LinuxCommandError::Unavailable,
    }
}
