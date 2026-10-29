use super::{
    FS_READ, HANDLED, LANDLOCK_CREATE_VERSION, LinuxCommandError, LinuxCommandExecutable,
    NativeFsProfile, RulesetAttr, add_rule, open_optional, path_descriptor, require_landlock_abi,
};
use std::{
    fs::File,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
pub(in crate::local_command_linux) fn build_helper_ruleset(
    workspace: &File,
    executable: &LinuxCommandExecutable<'_>,
    profile: NativeFsProfile,
) -> Result<OwnedFd, LinuxCommandError> {
    if !executable.is_sealed_snapshot() {
        return Err(LinuxCommandError::Unverified);
    }
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
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    add_rule(
        &fd,
        path_descriptor(workspace)?.as_raw_fd(),
        profile.allowed_access,
    )?;
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if let Some(system) = open_optional(path)? {
            add_rule(&fd, system.as_raw_fd(), FS_READ)?;
        }
    }
    // Child stdin uses the verified null device, never an inherited terminal.
    if let Some(null) = open_optional("/dev/null")? {
        add_rule(&fd, null.as_raw_fd(), (1 << 1) | (1 << 2))?;
    }
    if let Some(cache) = open_optional("/etc/ld.so.cache")? {
        add_rule(&fd, cache.as_raw_fd(), 1 << 2)?;
    }
    Ok(fd)
}
