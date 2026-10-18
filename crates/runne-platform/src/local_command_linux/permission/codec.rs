use super::super::{LinuxCommandError, snapshot::SealedExecutableSnapshot};
use runne_domain::task_run::{
    MAX_LOCAL_COMMAND_ARGV, MAX_LOCAL_COMMAND_BYTES, MAX_LOCAL_COMMAND_ENV, TaskRunLocalCommand,
};
use sha2::{Digest, Sha256};
use std::os::unix::fs::FileExt;
use std::{fs::File, os::fd::AsRawFd};

pub(super) const SCHEMA_LITERAL: &[u8] = b"runne:d21:x2-structured-command-schema:v1\0";
const ENVIRONMENT_DOMAIN: &[u8] = b"runne:d21:x2-environment:v1\0";
const TARGET_DOMAIN: &[u8] = b"runne:d21:x2-exec-target:v1\0";

pub(super) fn schema_digest() -> [u8; 32] {
    Sha256::digest(SCHEMA_LITERAL).into()
}

pub(super) fn environment_digest(
    command: &TaskRunLocalCommand,
) -> Result<[u8; 32], LinuxCommandError> {
    if command.argv().is_empty()
        || command.argv().len() > MAX_LOCAL_COMMAND_ARGV
        || command.env().len() > MAX_LOCAL_COMMAND_ENV
    {
        return Err(LinuxCommandError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(ENVIRONMENT_DOMAIN);
    hash.update(
        u32::try_from(command.env().len())
            .map_err(|_| LinuxCommandError::Invalid)?
            .to_be_bytes(),
    );
    let mut previous: Option<&str> = None;
    let mut total = command
        .executable()
        .value()
        .len()
        .checked_add(command.cwd().len())
        .ok_or(LinuxCommandError::Invalid)?;
    for argument in command.argv() {
        if argument.as_bytes().contains(&0) || argument.len() > 16 * 1024 {
            return Err(LinuxCommandError::Invalid);
        }
        total = total
            .checked_add(argument.len())
            .ok_or(LinuxCommandError::Invalid)?;
    }
    for (key, value) in command.env() {
        if key.is_empty()
            || key.len() > 128
            || value.len() > 16 * 1024
            || key.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
            || previous.is_some_and(|last| last >= key.as_str())
        {
            return Err(LinuxCommandError::Invalid);
        }
        previous = Some(key);
        total = total
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(LinuxCommandError::Invalid)?;
    }
    if total > MAX_LOCAL_COMMAND_BYTES {
        return Err(LinuxCommandError::Invalid);
    }
    for (key, value) in command.env() {
        frame(&mut hash, key.as_bytes())?;
        frame(&mut hash, value.as_bytes())?;
    }
    Ok(hash.finalize().into())
}

type TargetDigests = ([u8; 32], [u8; 32], [u8; 32], [u8; 32]);

pub(super) fn target_digest(
    snapshot: &SealedExecutableSnapshot,
    workspace: &File,
    cwd: &File,
) -> Result<TargetDigests, LinuxCommandError> {
    snapshot.validate_seals()?;
    let (object_id, generation) = snapshot.permission_identity();
    let workspace_id = descriptor_identity(workspace)?;
    let cwd_id = descriptor_identity(cwd)?;
    let executable = file_digest(snapshot.file())?;
    Ok((
        target_identity(object_id, generation, workspace_id, cwd_id, executable),
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
    let mut hash = Sha256::new();
    hash.update(TARGET_DOMAIN);
    hash.update(object_id);
    hash.update(generation.to_be_bytes());
    hash.update(workspace);
    hash.update(cwd);
    hash.update(executable);
    hash.finalize().into()
}

pub(super) fn descriptor_identity(file: &File) -> Result<[u8; 32], LinuxCommandError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    let mut hash = Sha256::new();
    hash.update(b"runne:d21:x2-held-fd:v1\0");
    hash.update((stat.st_dev as u64).to_be_bytes());
    hash.update((stat.st_ino as u64).to_be_bytes());
    Ok(hash.finalize().into())
}

fn file_digest(file: &File) -> Result<[u8; 32], LinuxCommandError> {
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let count = file
            .read_at(&mut bytes, offset)
            .map_err(|_| LinuxCommandError::Unavailable)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| LinuxCommandError::Invalid)?)
            .ok_or(LinuxCommandError::Invalid)?;
        hash.update(&bytes[..count]);
    }
    if offset == 0 {
        return Err(LinuxCommandError::Invalid);
    }
    Ok(hash.finalize().into())
}

fn frame(hash: &mut Sha256, bytes: &[u8]) -> Result<(), LinuxCommandError> {
    hash.update(
        u32::try_from(bytes.len())
            .map_err(|_| LinuxCommandError::Invalid)?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(())
}
