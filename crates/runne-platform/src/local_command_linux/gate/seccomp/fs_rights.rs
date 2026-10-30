use super::Program;
use crate::local_command_linux::policy::NativeFsProfile;

pub(super) fn append(program: &mut Program, profile: NativeFsProfile) {
    // Landlock does not mediate path metadata changes outside bounded roots.
    if !profile.write_allowed || !profile.metadata_allowed {
        for syscall in write_and_metadata_syscalls() {
            program.deny_syscall(syscall);
        }
    }
    if !profile.rename_allowed {
        for syscall in [libc::SYS_rename, libc::SYS_renameat, libc::SYS_renameat2] {
            program.deny_syscall(syscall);
        }
    }
    if profile.allowed_access & (1 << 7) == 0 {
        program.deny_syscall(libc::SYS_link);
        program.deny_syscall(libc::SYS_linkat);
    }
}

fn write_and_metadata_syscalls() -> [libc::c_long; 19] {
    [
        libc::SYS_chmod,
        libc::SYS_fchmod,
        libc::SYS_fchmodat,
        libc::SYS_fchmodat2,
        libc::SYS_chown,
        libc::SYS_fchown,
        libc::SYS_lchown,
        libc::SYS_fchownat,
        libc::SYS_utime,
        libc::SYS_utimes,
        libc::SYS_futimesat,
        libc::SYS_utimensat,
        libc::SYS_setxattr,
        libc::SYS_lsetxattr,
        libc::SYS_fsetxattr,
        libc::SYS_removexattr,
        libc::SYS_lremovexattr,
        libc::SYS_fremovexattr,
        libc::SYS_fallocate,
    ]
}
