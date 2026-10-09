use super::{GatedLinuxChild, LinuxCommandError, gate};
#[path = "child/composite.rs"]
pub(super) mod composite;
#[path = "child/output.rs"]
pub(super) mod output;
#[path = "child/stdio.rs"]
pub(super) mod stdio;
#[path = "child/supervision.rs"]
pub(super) mod supervision;
use crate::process_managed_area::LinuxManagedArea;
use rustix::process::Pid;
use std::ffi::CString;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

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

pub(super) struct SpawnSpec<'area, 'input> {
    pub exe: &'input File,
    pub workspace: &'input File,
    pub cwd: &'input File,
    pub ruleset: Option<&'input OwnedFd>,
    pub argv: &'input [CString],
    pub env: &'input [CString],
    pub area: &'area LinuxManagedArea,
    pub stdio: stdio::CommandStdio,
    pub composite: Option<&'input composite::PreparedComposite>,
    pub network_none: bool,
    pub filesystem_profile: Option<super::policy::NativeFsProfile>,
}

pub(super) fn spawn<'a>(spec: SpawnSpec<'a, '_>) -> Result<GatedLinuxChild<'a>, LinuxCommandError> {
    let SpawnSpec {
        exe,
        workspace,
        cwd,
        ruleset,
        argv,
        env,
        area,
        mut stdio,
        composite,
        network_none,
        filesystem_profile,
    } = spec;
    if area.is_populated().map_err(|_| LinuxCommandError::Area)? {
        return Err(LinuxCommandError::Area);
    }
    let seccomp_filter =
        gate::prepare_seccomp(composite.is_some(), network_none, filesystem_profile)
            .ok_or(LinuxCommandError::Unavailable)?;
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
    let base_keep = [
        supervision::dup(child_socket.as_raw_fd())?,
        supervision::dup(exe.as_raw_fd())?,
        supervision::dup(cwd.as_raw_fd())?,
        supervision::dup(workspace.as_raw_fd())?,
        ruleset.map_or_else(
            || supervision::dup(cwd.as_raw_fd()),
            |fd| supervision::dup(fd.as_raw_fd()),
        )?,
        supervision::dup(stdio.child_fds[0].as_raw_fd())?,
        supervision::dup(stdio.child_fds[1].as_raw_fd())?,
        supervision::dup(stdio.child_fds[2].as_raw_fd())?,
    ];
    let (protected_keep, mount_targets, device_targets, device_source_paths, protected_regular) =
        match composite {
            Some(prepared) => {
                let (descriptors, targets, regular_indices, dev_targets, dev_sources) =
                    prepared.child_descriptors()?;
                let regular_fds = regular_indices
                    .iter()
                    .map(|index| descriptors[*index].as_raw_fd())
                    .collect();
                (descriptors, targets, dev_targets, dev_sources, regular_fds)
            }
            None => (Vec::new(), Vec::new(), Vec::new(), Vec::new(), Vec::new()),
        };
    let mount_target_ptrs = mount_targets.iter().map(|target| target.as_ptr()).collect();
    let device_target_ptrs = device_targets
        .iter()
        .map(|target| target.as_ptr())
        .collect();
    let device_source_path_ptrs = device_source_paths
        .iter()
        .map(|source| source.as_ptr())
        .collect();
    let mut retained = base_keep
        .iter()
        .map(|fd| fd.as_raw_fd())
        .chain(protected_keep.iter().map(|fd| fd.as_raw_fd()))
        .collect::<Vec<_>>();
    retained.sort_unstable();
    let protected_fd_numbers = protected_keep.iter().map(|fd| fd.as_raw_fd()).collect();
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
    supervision::validate_sigchld()?;
    let mut signal_mask = SignalMaskGuard::block_all()?;
    let parent_pid = unsafe { libc::getpid() };
    let mut pidfd_raw = -1i32;
    let namespace_flags = if composite.is_some() {
        (libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWPID) as u64
    } else {
        0
    };
    let args = CloneArgs {
        flags: 0x1000 | namespace_flags,
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
            base_keep,
            protected_keep,
            protected_fd_numbers,
            retained,
            parent_pid,
            arg_ptrs.as_ptr(),
            env_ptrs.as_ptr(),
            ruleset.is_some(),
            composite.is_some(),
            network_none,
            &seccomp_filter,
            mount_target_ptrs,
            protected_regular,
            device_target_ptrs,
            device_source_path_ptrs,
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
        supervision::kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Unverified);
    }
    drop(child_socket);
    if composite.is_some()
        && composite::map_child_identity(pid.as_raw_pid(), parent_socket.as_raw_fd()).is_err()
    {
        supervision::kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Unavailable);
    }
    if supervision::read_ready(parent_socket.as_raw_fd()).is_err() {
        supervision::kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Unavailable);
    }
    if composite.is_some() && unsafe { libc::kill(pid.as_raw_pid(), libc::SIGSTOP) } != 0 {
        supervision::kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Unverified);
    }
    if let Err(error) = supervision::wait_stopped(pid) {
        supervision::kill_and_reap(pid, &pidfd);
        return Err(error);
    }
    if area.attach_gated_process(pid.as_raw_pid() as u32).is_err() {
        supervision::kill_and_reap(pid, &pidfd);
        return Err(LinuxCommandError::Area);
    }
    Ok(GatedLinuxChild {
        pid: pid.as_raw_pid(),
        pidfd,
        go: parent_socket,
        area,
        released: false,
        go_written: false,
        reaped: false,
        exit_code: None,
        leader_exit: None,
        output: stdio.output.take(),
    })
}
