use super::LinuxCommandError;
use super::spec::LinuxCommandExecutable;
use rustix::fs::{CWD, Mode, OFlags, ResolveFlags, fstat, fstatfs, openat2};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

#[path = "policy/composite_fs.rs"]
mod composite_fs;
#[path = "policy/helper_fs.rs"]
mod helper_fs;
pub(in crate::local_command_linux) use composite_fs::preflight_composite_ruleset;
pub(in crate::local_command_linux) use composite_fs::{
    NativeFsProfile, build_composite_ruleset, native_fs_profile,
};
pub(in crate::local_command_linux) use helper_fs::build_helper_ruleset;
use std::path::PathBuf;

const CGROUP2_MAGIC: i64 = 0x6367_7270;
const FS_READ: u64 = 1 | 4 | 8;
const FS_WRITE: u64 = 1 << 1
    | 1 << 4
    | 1 << 5
    | 1 << 6
    | 1 << 7
    | 1 << 8
    | 1 << 9
    | 1 << 10
    | 1 << 11
    | 1 << 12
    | 1 << 13
    | 1 << 14;
const HANDLED: u64 = FS_READ | FS_WRITE;
const LANDLOCK_CREATE_VERSION: u32 = 1;
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}
#[repr(C)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

pub(super) fn validate_descriptors(
    exe: &File,
    workspace: &File,
    cwd: &File,
) -> Result<(), LinuxCommandError> {
    let workspace_fs = fstatfs(workspace).map_err(|_| LinuxCommandError::Unavailable)?;
    if workspace_fs.f_type == CGROUP2_MAGIC {
        return Err(LinuxCommandError::Invalid);
    }
    let ws = fstat(workspace).map_err(|_| LinuxCommandError::Invalid)?;
    let root = File::open("/").map_err(|_| LinuxCommandError::Unavailable)?;
    let root_stat = fstat(&root).map_err(|_| LinuxCommandError::Unavailable)?;
    if ws.st_dev == root_stat.st_dev && ws.st_ino == root_stat.st_ino {
        return Err(LinuxCommandError::Invalid);
    }
    let ex = fstat(exe).map_err(|_| LinuxCommandError::Invalid)?;
    if ex.st_mode & libc::S_IFMT != libc::S_IFREG || ex.st_mode & 0o111 == 0 {
        return Err(LinuxCommandError::Invalid);
    }
    ensure_beneath(workspace, cwd)?;
    reject_nested_cgroup_mount(workspace)?;
    Ok(())
}

fn ensure_beneath(workspace: &File, cwd: &File) -> Result<(), LinuxCommandError> {
    let base = fstat(workspace).map_err(|_| LinuxCommandError::Invalid)?;
    let mut current = cwd.try_clone().map_err(|_| LinuxCommandError::Invalid)?;
    for _ in 0..256 {
        let stat = fstat(&current).map_err(|_| LinuxCommandError::Invalid)?;
        let fs = fstatfs(&current).map_err(|_| LinuxCommandError::Invalid)?;
        if fs.f_type == CGROUP2_MAGIC {
            return Err(LinuxCommandError::Invalid);
        }
        if stat.st_dev == base.st_dev && stat.st_ino == base.st_ino {
            return Ok(());
        }
        let next = unsafe {
            libc::openat(
                current.as_raw_fd(),
                c"..".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if next < 0 {
            return Err(LinuxCommandError::Invalid);
        }
        // SAFETY: openat returned a new owned directory descriptor.
        current = unsafe { File::from_raw_fd(next) };
        let parent = fstat(&current).map_err(|_| LinuxCommandError::Invalid)?;
        if parent.st_dev == stat.st_dev && parent.st_ino == stat.st_ino {
            break;
        }
    }
    Err(LinuxCommandError::Invalid)
}

fn reject_nested_cgroup_mount(workspace: &File) -> Result<(), LinuxCommandError> {
    let link = std::fs::read_link(format!("/proc/self/fd/{}", workspace.as_raw_fd()))
        .map_err(|_| LinuxCommandError::Unavailable)?;
    if !link.is_absolute() || link.as_os_str().as_bytes().ends_with(b" (deleted)") {
        return Err(LinuxCommandError::Invalid);
    }
    let base = std::fs::canonicalize(&link).map_err(|_| LinuxCommandError::Invalid)?;
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|_| LinuxCommandError::Unavailable)?;
    for line in mounts.lines() {
        let Some((_, after)) = line.split_once(" - ") else {
            return Err(LinuxCommandError::Unavailable);
        };
        if after.split_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let mount = line
            .split_whitespace()
            .nth(4)
            .ok_or(LinuxCommandError::Unavailable)?;
        let mount_path = PathBuf::from(decode_mount(mount)?);
        if mount_path.starts_with(&base) && mount_path != base {
            return Err(LinuxCommandError::Invalid);
        }
    }
    Ok(())
}
fn decode_mount(raw: &str) -> Result<String, LinuxCommandError> {
    let mut out = Vec::new();
    let b = raw.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 3 >= b.len() {
                return Err(LinuxCommandError::Unavailable);
            }
            let n = std::str::from_utf8(&b[i + 1..i + 4])
                .ok()
                .and_then(|s| u8::from_str_radix(s, 8).ok())
                .ok_or(LinuxCommandError::Unavailable)?;
            out.push(n);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| LinuxCommandError::Unavailable)
}

pub(super) fn build_ruleset(
    workspace: &File,
    executable: &LinuxCommandExecutable<'_>,
) -> Result<OwnedFd, LinuxCommandError> {
    // ABI 3 is mandatory: REFER and TRUNCATE must be handled, not silently omitted.
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
    // SAFETY: successful create_ruleset returns a new owned descriptor.
    let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let workspace_rule = path_descriptor(workspace)?;
    add_rule(&fd, workspace_rule.as_raw_fd(), HANDLED)?;
    for path in ["/usr", "/bin", "/lib", "/lib64"] {
        if let Some(system_fd) = open_optional(path)? {
            add_rule(&fd, system_fd.as_raw_fd(), FS_READ)?;
        }
    }
    if let Some(cache) = open_optional("/etc/ld.so.cache")? {
        add_rule(&fd, cache.as_raw_fd(), 1 << 2)?;
    }
    if !executable.is_sealed_snapshot() {
        let executable_rule = path_descriptor(executable.file())?;
        add_rule(&fd, executable_rule.as_raw_fd(), FS_READ & !8)?;
    }
    Ok(fd)
}
fn add_rule(
    ruleset: &OwnedFd,
    parent_fd: i32,
    allowed_access: u64,
) -> Result<(), LinuxCommandError> {
    let attr = PathBeneathAttr {
        allowed_access,
        parent_fd,
    };
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            LANDLOCK_RULE_PATH_BENEATH,
            &attr,
            0u32,
        )
    };
    (rc == 0)
        .then_some(())
        .ok_or(LinuxCommandError::Unavailable)
}

fn path_descriptor(file: &File) -> Result<OwnedFd, LinuxCommandError> {
    let path = format!("/proc/self/fd/{}", file.as_raw_fd());
    openat2(
        CWD,
        path.as_str(),
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    )
    .map_err(|_| LinuxCommandError::Unavailable)
}
fn open_optional(path: &str) -> Result<Option<OwnedFd>, LinuxCommandError> {
    match openat2(
        CWD,
        path,
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(_) => Err(LinuxCommandError::Unavailable),
    }
}

fn require_landlock_abi(abi: i64) -> Result<(), LinuxCommandError> {
    if abi >= 3 {
        Ok(())
    } else {
        Err(LinuxCommandError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{LinuxCommandError, require_landlock_abi};

    #[test]
    fn unsupported_landlock_abi_fails_closed_before_launch() {
        eprintln!("RUN: unsupported_landlock_abi_fails_closed_before_launch");
        assert_eq!(require_landlock_abi(2), Err(LinuxCommandError::Unavailable));
        assert_eq!(require_landlock_abi(3), Ok(()));
    }
}
