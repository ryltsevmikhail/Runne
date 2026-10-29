use super::policy::HostResult;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;

pub(super) fn terminal() -> HostResult<File> {
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || uid != unsafe { libc::getuid() } {
        return Err("credential host requires an ordinary owner session");
    }
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
    {
        return Err("credential host cannot disable process dumps");
    }
    let terminal = File::options()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")
        .map_err(|_| "a local foreground terminal is required")?;
    let fd = terminal.as_raw_fd();
    let foreground = unsafe { libc::tcgetpgrp(fd) };
    if unsafe { libc::isatty(fd) } != 1
        || foreground <= 0
        || foreground != unsafe { libc::getpgrp() }
    {
        return Err("a local owner-controlled foreground terminal is required");
    }
    Ok(terminal)
}
