use super::super::spec::LinuxCommandExecutable;
use super::{
    HANDLED, LANDLOCK_CREATE_VERSION, LinuxCommandError, RulesetAttr, add_rule, path_descriptor,
    require_landlock_abi,
};
use runne_application::permission_modes::FilesystemPermission;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
const REMOVE_DIR: u64 = 1 << 4;
const REMOVE_FILE: u64 = 1 << 5;
const MAKE_CHAR: u64 = 1 << 6;
const MAKE_DIR: u64 = 1 << 7;
const MAKE_REG: u64 = 1 << 8;
const MAKE_SOCK: u64 = 1 << 9;
const MAKE_FIFO: u64 = 1 << 10;
const MAKE_BLOCK: u64 = 1 << 11;
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const FS_CREATE: u64 =
    MAKE_CHAR | MAKE_DIR | MAKE_REG | MAKE_SOCK | MAKE_FIFO | MAKE_BLOCK | MAKE_SYM;

#[derive(Debug, Clone, Copy)]
pub(in crate::local_command_linux) struct NativeFsProfile {
    pub(in crate::local_command_linux) allowed_access: u64,
    pub(in crate::local_command_linux) write_allowed: bool,
    pub(in crate::local_command_linux) rename_allowed: bool,
}

pub(in crate::local_command_linux) fn native_fs_profile(
    permissions: &std::collections::BTreeSet<FilesystemPermission>,
) -> Result<NativeFsProfile, LinuxCommandError> {
    let read = permissions.contains(&FilesystemPermission::Read);
    let create = permissions.contains(&FilesystemPermission::Create);
    let write = permissions.contains(&FilesystemPermission::Write);
    let delete = permissions.contains(&FilesystemPermission::Delete);
    if create && !write {
        return Err(LinuxCommandError::CompositePolicyUnenforceable);
    }
    // ProcessStart is part of the broad command profile and is independent of FsRead.
    let mut allowed_access = EXECUTE;
    if read {
        allowed_access |= READ_FILE | READ_DIR;
    }
    if write {
        allowed_access |= WRITE_FILE | TRUNCATE;
    }
    if delete {
        allowed_access |= REMOVE_DIR | REMOVE_FILE;
    }
    if create {
        allowed_access |= FS_CREATE | REFER;
    }
    Ok(NativeFsProfile {
        allowed_access,
        write_allowed: write,
        rename_allowed: create && delete && write,
    })
}

pub(in crate::local_command_linux) fn build_composite_ruleset(
    profile: NativeFsProfile,
    executable: &LinuxCommandExecutable<'_>,
) -> Result<OwnedFd, LinuxCommandError> {
    if !executable.is_sealed_snapshot() {
        return Err(LinuxCommandError::CompositePolicyUnenforceable);
    }
    create_ruleset(profile)
}

pub(in crate::local_command_linux) fn preflight_composite_ruleset(
    profile: NativeFsProfile,
) -> Result<(), LinuxCommandError> {
    drop(create_ruleset(profile)?);
    Ok(())
}

fn create_ruleset(profile: NativeFsProfile) -> Result<OwnedFd, LinuxCommandError> {
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_VERSION,
        )
    };
    require_landlock_abi(abi)?;
    let attr = RulesetAttr {
        handled_access_fs: HANDLED,
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<RulesetAttr>(),
            0u32,
        )
    };
    if raw < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    let ruleset = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let root = File::open("/").map_err(|_| LinuxCommandError::Unavailable)?;
    let root = path_descriptor(&root)?;
    add_rule(&ruleset, root.as_raw_fd(), profile.allowed_access)?;
    Ok(ruleset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn mask_contains_only_requested_abi3_rights_and_create_requires_write() {
        assert_eq!(HANDLED, (1 << 15) - 1);
        let profile = native_fs_profile(&BTreeSet::from([
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
        ]))
        .unwrap();
        assert_eq!(
            profile.allowed_access,
            EXECUTE | READ_FILE | READ_DIR | WRITE_FILE | TRUNCATE | FS_CREATE | REFER
        );
        assert!(!profile.rename_allowed);
        assert!(matches!(
            native_fs_profile(&BTreeSet::from([FilesystemPermission::Create])),
            Err(LinuxCommandError::CompositePolicyUnenforceable)
        ));
        assert_eq!(
            native_fs_profile(&BTreeSet::from([FilesystemPermission::Read]))
                .unwrap()
                .allowed_access,
            EXECUTE | READ_FILE | READ_DIR
        );
        assert_eq!(
            native_fs_profile(&BTreeSet::from([FilesystemPermission::Write]))
                .unwrap()
                .allowed_access,
            EXECUTE | WRITE_FILE | TRUNCATE
        );
        assert_eq!(
            native_fs_profile(&BTreeSet::from([FilesystemPermission::Delete]))
                .unwrap()
                .allowed_access,
            EXECUTE | REMOVE_DIR | REMOVE_FILE
        );
    }

    #[test]
    fn all_rights_enable_rename_and_delete_only_adds_remove_bits() {
        let profile = native_fs_profile(&BTreeSet::from([
            FilesystemPermission::Read,
            FilesystemPermission::Create,
            FilesystemPermission::Write,
            FilesystemPermission::Delete,
        ]))
        .unwrap();
        assert!(profile.rename_allowed);
        assert_eq!(
            profile.allowed_access & (REMOVE_DIR | REMOVE_FILE),
            REMOVE_DIR | REMOVE_FILE
        );
    }
}
