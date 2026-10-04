use super::{GatedLinuxChild, LinuxCommandError, gate};
use crate::process_managed_area::LinuxManagedArea;
use rustix::process::Pid;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

const GATE_TIMEOUT: Duration = Duration::from_secs(3);
const FD_MIN: i32 = 50;

#[repr(C)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

struct SignalMaskGuard {
    old: libc::sigset_t,
    active: bool,
}
impl SignalMaskGuard {
    fn block_all() -> Result<Self, LinuxCommandError> {
        let mut full = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        let mut old = unsafe { std::mem::zeroed::<libc::sigset_t>() };
        // SAFETY: both pointers reference initialized signal-set storage.
        if unsafe { libc::sigfillset(&mut full) } != 0
            || unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &full, &mut old) } != 0
        {
            return Err(LinuxCommandError::Unavailable);
        }
        Ok(Self { old, active: true })
    }
    fn restore(&mut self) -> Result<(), LinuxCommandError> {
        // SAFETY: old was returned by pthread_sigmask for this calling thread.
        if unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut()) } != 0
        {
            return Err(LinuxCommandError::Unverified);
        }
        self.active = false;
        Ok(())
    }
}
impl Drop for SignalMaskGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: best-effort restoration of this thread's saved signal mask.
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, &self.old, std::ptr::null_mut());
            }
        }
    }
}

pub(super) fn spawn<'a>(
    exe: &File,
    workspace: &File,
    cwd: &File,
    ruleset: &OwnedFd,
    argv: &[CString],
    env: &[CString],
    area: &'a LinuxManagedArea,
) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
    if area.is_populated().map_err(|_| LinuxCommandError::Area)? {
        return Err(LinuxCommandError::Area);
    }
    let mut pair = [0; 2];
    // SOCK_STREAM carries READY/GO; send(MSG_NOSIGNAL) prevents SIGPIPE on peer death.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(LinuxCommandError::Unavailable);
    }
    // SAFETY: successful socketpair returned two owned descriptors.
    let parent_socket = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let child_socket = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    let null = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")
        .map_err(|_| LinuxCommandError::Unavailable)?;
    let keep = [
        dup(child_socket.as_raw_fd())?,
        dup(exe.as_raw_fd())?,
        dup(cwd.as_raw_fd())?,
        dup(workspace.as_raw_fd())?,
        dup(ruleset.as_raw_fd())?,
        dup(null.as_raw_fd())?,
    ];
    let mut retained = keep.each_ref().map(|fd| fd.as_raw_fd());
    retained.sort_unstable();
    let arg_ptrs: Vec<*const u8> = argv
        .iter()
        .map(|arg| arg.as_ptr().cast())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let env_ptrs: Vec<*const u8> = env
        .iter()
        .map(|item| item.as_ptr().cast())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    validate_sigchld()?;
    let mut signal_mask = SignalMaskGuard::block_all()?;
    let parent_pid = unsafe { libc::getpid() };
    let mut pidfd_raw = -1i32;
    let args = CloneArgs {
        flags: 0x1000,
        pidfd: (&mut pidfd_raw as *mut i32) as u64,
        child_tid: 0,
        parent_tid: 0,
        exit_signal: libc::SIGCHLD as u64,
        stack: 0,
        stack_size: 0,
        tls: 0,
        set_tid: 0,
        set_tid_size: 0,
        cgroup: 0,
    };
    let pid_raw =
        unsafe { libc::syscall(libc::SYS_clone3, &args, std::mem::size_of::<CloneArgs>()) };
    if pid_raw == 0 {
        gate::enter(
            keep,
            retained,
            parent_pid,
            arg_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
        );
    }
    let restored = signal_mask.restore().is_ok();
    if pid_raw < 0 || pidfd_raw < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    let pid = Pid::from_raw(pid_raw as i32).ok_or(LinuxCommandError::Unverified)?;
    // SAFETY: CLONE_PIDFD returned this owned descriptor atomically with the child.
    let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd_raw) };
    if !restored {
        kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Unverified);
    }
    drop(child_socket);
    if read_ready(parent_socket.as_raw_fd()).is_err() {
        kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Unavailable);
    }
    if let Err(error) = wait_stopped(pid) {
        kill_and_reap(pid, &pidfd);
        return Err(error);
    }
    if area.attach_gated_process(pid.as_raw_pid() as u32).is_err() {
        kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Area);
    }
    Ok(GatedLinuxChild {
        pid: pid.as_raw_pid(),
        pidfd,
        go: parent_socket,
        area,
        released: false,
        reaped: false,
    })
}

fn validate_sigchld() -> Result<(), LinuxCommandError> {
    let mut action = unsafe { std::mem::zeroed::<libc::sigaction>() };
    // SAFETY: querying SIGCHLD disposition writes into initialized output storage.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction == libc::SIG_IGN
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(LinuxCommandError::Unavailable);
    }
    Ok(())
}
fn dup(fd: i32) -> Result<OwnedFd, LinuxCommandError> {
    // SAFETY: F_DUPFD_CLOEXEC returns a new descriptor on success.
    let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, FD_MIN) };
    if result < 0 {
        return Err(LinuxCommandError::Unavailable);
    }
    // SAFETY: fcntl returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(result) })
}
fn read_ready(fd: i32) -> Result<(), LinuxCommandError> {
    let deadline = Instant::now() + GATE_TIMEOUT;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(LinuxCommandError::Unverified);
        }
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll references one initialized pollfd and has a finite timeout.
        let result = unsafe { libc::poll(&mut poll, 1, remaining.as_millis() as i32) };
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if result != 1 {
            return Err(LinuxCommandError::Unverified);
        }
        let mut byte = 0u8;
        // SAFETY: byte is writable for one byte; recv is on the held control socket.
        if unsafe { libc::recv(fd, (&mut byte as *mut u8).cast(), 1, 0) } != 1 {
            return Err(LinuxCommandError::Unverified);
        }
        return if byte == b'R' {
            Ok(())
        } else {
            Err(LinuxCommandError::Unverified)
        };
    }
}
fn wait_stopped(pid: Pid) -> Result<(), LinuxCommandError> {
    let deadline = Instant::now() + GATE_TIMEOUT;
    loop {
        let mut status = 0;
        // SAFETY: status points to writable storage; pid remains our unreaped child.
        let got = unsafe {
            libc::waitpid(
                pid.as_raw_pid(),
                &mut status,
                libc::WNOHANG | libc::WUNTRACED,
            )
        };
        if got == pid.as_raw_pid() {
            return if libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == libc::SIGSTOP {
                Ok(())
            } else {
                Err(LinuxCommandError::Unverified)
            };
        }
        if got < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        if got < 0 || Instant::now() >= deadline {
            return Err(LinuxCommandError::Timeout);
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
pub(super) fn reap_bounded_or_defer(pid: i32) {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut status = 0;
        // SAFETY: status is writable and pid is our owned direct child.
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid
            || (result < 0 && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
        {
            return;
        }
        if Instant::now() >= deadline {
            let _ = std::thread::Builder::new().spawn(move || {
                loop {
                    let mut status = 0;
                    // SAFETY: this deferred reaper waits only for the owned direct child.
                    let result = unsafe { libc::waitpid(pid, &mut status, 0) };
                    if result == pid
                        || (result < 0
                            && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR))
                    {
                        break;
                    }
                }
            });
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn kill_and_reap(pid: Pid, pidfd: &OwnedFd) {
    let _ = rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL);
    reap_bounded_or_defer(pid.as_raw_pid());
}
