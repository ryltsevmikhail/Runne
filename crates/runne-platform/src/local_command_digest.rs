//! Platform-neutral digests binding a structured command to its exact target.
//!
//! Linux and macOS record the same closed facts. Keeping one encoder here means
//! a digest prepared on one adapter holds the same bytes as on the other, so a
//! stored binding cannot drift when the execution node changes platform. Only
//! the native proof of the held descriptors stays platform-specific.
#![allow(unsafe_code)]

use runne_domain::task_run::{
    MAX_LOCAL_COMMAND_ARGV, MAX_LOCAL_COMMAND_BYTES, MAX_LOCAL_COMMAND_ENV, TaskRunLocalCommand,
};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;

pub(crate) const SCHEMA_LITERAL: &[u8] = b"runne:d21:x2-structured-command-schema:v1\0";
const ENVIRONMENT_DOMAIN: &[u8] = b"runne:d21:x2-environment:v1\0";
const TARGET_DOMAIN: &[u8] = b"runne:d21:x2-exec-target:v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"runne:d21:x2-held-fd:v1\0";

/// Failure to encode a bounded command fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DigestError {
    /// The command or held descriptor set violates a closed bound.
    Invalid,
    /// A held descriptor could not be inspected.
    Unavailable,
}

/// Returns the digest of the closed structured-command schema.
pub(crate) fn schema_digest() -> [u8; 32] {
    Sha256::digest(SCHEMA_LITERAL).into()
}

/// Returns the digest of the normalized, ordered command environment.
///
/// # Errors
/// Returns invalid when the command exceeds a closed bound or its environment
/// is not strictly ascending without duplicates.
pub(crate) fn environment_digest(command: &TaskRunLocalCommand) -> Result<[u8; 32], DigestError> {
    if command.argv().is_empty()
        || command.argv().len() > MAX_LOCAL_COMMAND_ARGV
        || command.env().len() > MAX_LOCAL_COMMAND_ENV
    {
        return Err(DigestError::Invalid);
    }
    let mut hash = Sha256::new();
    hash.update(ENVIRONMENT_DOMAIN);
    hash.update(
        u32::try_from(command.env().len())
            .map_err(|_| DigestError::Invalid)?
            .to_be_bytes(),
    );
    let mut previous: Option<&str> = None;
    let mut total = command
        .executable()
        .value()
        .len()
        .checked_add(command.cwd().len())
        .ok_or(DigestError::Invalid)?;
    for argument in command.argv() {
        if argument.as_bytes().contains(&0) || argument.len() > 16 * 1024 {
            return Err(DigestError::Invalid);
        }
        total = total
            .checked_add(argument.len())
            .ok_or(DigestError::Invalid)?;
    }
    for (key, value) in command.env() {
        if key.is_empty()
            || key.len() > 128
            || value.len() > 16 * 1024
            || key.as_bytes().contains(&0)
            || value.as_bytes().contains(&0)
            || previous.is_some_and(|last| last >= key.as_str())
        {
            return Err(DigestError::Invalid);
        }
        previous = Some(key);
        total = total
            .checked_add(key.len())
            .and_then(|n| n.checked_add(value.len()))
            .ok_or(DigestError::Invalid)?;
    }
    if total > MAX_LOCAL_COMMAND_BYTES {
        return Err(DigestError::Invalid);
    }
    for (key, value) in command.env() {
        frame(&mut hash, key.as_bytes())?;
        frame(&mut hash, value.as_bytes())?;
    }
    Ok(hash.finalize().into())
}

/// Returns the identity digest of a held descriptor from its device and inode.
///
/// # Errors
/// Returns unavailable when `fstat` on the held descriptor fails.
pub(crate) fn descriptor_identity(file: &File) -> Result<[u8; 32], DigestError> {
    let mut stat = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(file.as_raw_fd(), &mut stat) } != 0 {
        return Err(DigestError::Unavailable);
    }
    let mut hash = Sha256::new();
    hash.update(DESCRIPTOR_DOMAIN);
    hash.update((stat.st_dev as u64).to_be_bytes());
    hash.update((stat.st_ino as u64).to_be_bytes());
    Ok(hash.finalize().into())
}

/// Returns the digest of the exact bytes held by a descriptor.
///
/// # Errors
/// Returns invalid for an empty object and unavailable when reading fails.
pub(crate) fn file_digest(file: &File) -> Result<[u8; 32], DigestError> {
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 64 * 1024];
    let mut offset = 0u64;
    loop {
        let count = file
            .read_at(&mut bytes, offset)
            .map_err(|_| DigestError::Unavailable)?;
        if count == 0 {
            break;
        }
        offset = offset
            .checked_add(u64::try_from(count).map_err(|_| DigestError::Invalid)?)
            .ok_or(DigestError::Invalid)?;
        hash.update(&bytes[..count]);
    }
    if offset == 0 {
        return Err(DigestError::Invalid);
    }
    Ok(hash.finalize().into())
}

/// Returns the closed target identity over the sealed object and held paths.
pub(crate) fn target_identity(
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

fn frame(hash: &mut Sha256, bytes: &[u8]) -> Result<(), DigestError> {
    hash.update(
        u32::try_from(bytes.len())
            .map_err(|_| DigestError::Invalid)?
            .to_be_bytes(),
    );
    hash.update(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use runne_domain::task_run::{TaskRunExecutable, TaskRunLocalCommand};

    fn command() -> TaskRunLocalCommand {
        TaskRunLocalCommand::new(
            TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
            ".".into(),
            vec!["bin/tool".into(), "--check".into()],
            vec![("B".into(), "2".into()), ("A".into(), "1".into())],
        )
        .unwrap()
    }

    fn hex(value: &[u8]) -> String {
        value.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    #[test]
    fn closed_schema_matches_the_independent_vector() {
        assert_eq!(
            hex(&schema_digest()),
            "e0e0ff8d1691c36bb899e2c8625d6bce93ffb69ad1b2aca9cbe3cf536a654ad8"
        );
    }

    #[test]
    fn sorted_environment_matches_the_independent_vector() {
        assert_eq!(
            hex(&environment_digest(&command()).unwrap()),
            "00c06d3bec738112a014abdf2b74d901e0be63bdd7b893c815669a405d56667e"
        );
    }

    #[test]
    fn target_identity_matches_the_independent_fixed_byte_vector() {
        assert_eq!(
            hex(&target_identity(
                [0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 7],
                1,
                [0x11; 32],
                [0x22; 32],
                [
                    0x8e, 0x70, 0x4f, 0x8a, 0x01, 0x1f, 0x40, 0x5d, 0x54, 0xfd, 0x54, 0xe2, 0x58,
                    0x55, 0xa8, 0xc3, 0x82, 0x7f, 0x0e, 0x16, 0x61, 0xfc, 0x45, 0x8e, 0xbe, 0x54,
                    0x7e, 0x9b, 0xfd, 0x7a, 0x7f, 0x45,
                ],
            )),
            "b8dfcdcf008852fb633746c8aab3c154b4c460214ade1b252500e956221a49f5"
        );
    }

    #[test]
    fn environment_digest_binds_values_and_frames_each_entry() {
        let executable = TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap();
        let build = |env: Vec<(String, String)>| {
            TaskRunLocalCommand::new(executable.clone(), ".".into(), vec!["bin/tool".into()], env)
                .unwrap()
        };
        let base = build(vec![("A".into(), "BC".into())]);
        assert_eq!(
            environment_digest(&base),
            environment_digest(&build(vec![("A".into(), "BC".into())]))
        );
        assert_ne!(
            environment_digest(&base),
            environment_digest(&build(vec![("AB".into(), "C".into())]))
        );
    }

    #[test]
    fn descriptor_identity_distinguishes_distinct_objects() {
        let directory = tempfile::tempdir().unwrap();
        let first = std::fs::File::open(directory.path()).unwrap();
        let second = std::fs::File::open(std::env::temp_dir()).unwrap();
        assert_ne!(
            descriptor_identity(&first).unwrap(),
            descriptor_identity(&second).unwrap()
        );
        assert_eq!(
            descriptor_identity(&first).unwrap(),
            descriptor_identity(&first.try_clone().unwrap()).unwrap()
        );
    }
}
