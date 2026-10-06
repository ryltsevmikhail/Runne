//! Closed syscall checks for namespace escape and reserved kernel controls.

const LOAD: u16 = 0x20;
const JEQ: u16 = 0x15;
const JSET: u16 = 0x45;
const AND: u16 = 0x54;
const RET: u16 = 0x06;
const DENY: u32 = 0x0005_0000 | libc::EPERM as u32;
const ALLOW: u32 = 0x7fff_0000;

/// Worst-case instruction budget for the legal scope combination
/// `SameUserCompositeV1` + `NetworkScope::None` on x86_64: 4 arch prologue,
/// 2 x32 deny, 22 namespace, 2 clone3, 46 kernel-control, 6 dumpable,
/// 42 network-none, 6 clone-ns, 1 allow = 131. The capacity keeps headroom
/// so future syscall additions cannot overflow the array.
const PROGRAM_CAPACITY: usize = 192;

struct Program([libc::sock_filter; PROGRAM_CAPACITY], usize);

impl Program {
    fn new() -> Self {
        Self(
            [libc::sock_filter {
                code: 0,
                jt: 0,
                jf: 0,
                k: 0,
            }; PROGRAM_CAPACITY],
            0,
        )
    }

    fn push(&mut self, code: u16, jt: u8, jf: u8, value: u32) {
        self.0[self.1] = libc::sock_filter {
            code,
            jt,
            jf,
            k: value,
        };
        self.1 += 1;
    }

    fn deny_syscall(&mut self, syscall: libc::c_long) {
        self.push(JEQ, 0, 1, syscall as u32);
        self.push(RET, 0, 0, DENY);
    }

    fn deny_syscall_errno(&mut self, syscall: libc::c_long, error: i32) {
        self.push(JEQ, 0, 1, syscall as u32);
        self.push(RET, 0, 0, 0x0005_0000 | error as u32);
    }

    fn finish(self) -> i32 {
        let mut program = libc::sock_fprog {
            len: self.1 as u16,
            filter: self.0.as_ptr() as *mut libc::sock_filter,
        };
        unsafe {
            libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &mut program,
            )
        }
    }
}

pub(super) unsafe fn install(composite: bool, network_none: bool) -> i32 {
    let Some(arch) = audit_arch() else { return -1 };
    build(arch, composite, network_none).finish()
}

fn build(arch: u32, composite: bool, network_none: bool) -> Program {
    let mut filter = Program::new();
    filter.push(LOAD, 0, 0, 4);
    filter.push(JEQ, 1, 0, arch);
    filter.push(RET, 0, 0, 0x8000_0000);
    filter.push(LOAD, 0, 0, 0);
    #[cfg(target_arch = "x86_64")]
    {
        filter.push(JSET, 0, 1, 0x4000_0000);
        filter.push(RET, 0, 0, DENY);
    }
    for syscall in namespace_syscalls() {
        filter.deny_syscall(syscall);
    }
    filter.deny_syscall_errno(libc::SYS_clone3, libc::ENOSYS);
    if composite {
        for syscall in kernel_control_syscalls() {
            filter.deny_syscall(syscall);
        }
        filter.deny_dumpable_changes();
    }
    if network_none {
        filter.deny_network_syscalls();
    } else if composite {
        filter.deny_syscall(libc::SYS_socketpair);
        filter.deny_af_unix_and_non_ip_sockets();
    }
    deny_namespace_clone(&mut filter);
    filter.push(RET, 0, 0, ALLOW);
    filter
}

impl Program {
    #[cfg(test)]
    fn instruction_count(&self) -> usize {
        self.1
    }

    fn deny_network_syscalls(&mut self) {
        for syscall in [
            libc::SYS_socket,
            libc::SYS_socketpair,
            libc::SYS_connect,
            libc::SYS_bind,
            libc::SYS_listen,
            libc::SYS_accept,
            libc::SYS_accept4,
            libc::SYS_getsockname,
            libc::SYS_getpeername,
            libc::SYS_sendto,
            libc::SYS_recvfrom,
            libc::SYS_sendmsg,
            libc::SYS_recvmsg,
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_shutdown,
            libc::SYS_setsockopt,
            libc::SYS_getsockopt,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            self.deny_syscall(syscall);
        }
    }

    fn deny_af_unix_and_non_ip_sockets(&mut self) {
        let start = self.1;
        self.push(JEQ, 0, 0, libc::SYS_socket as u32);
        self.push(LOAD, 0, 0, 16);
        self.push(JEQ, 2, 0, libc::AF_INET as u32);
        self.push(JEQ, 1, 0, libc::AF_INET6 as u32);
        self.push(RET, 0, 0, DENY);
        self.push(LOAD, 0, 0, 24);
        self.push(AND, 0, 0, 0xf);
        self.push(JEQ, 0, 1, libc::SOCK_RAW as u32);
        self.push(RET, 0, 0, DENY);
        self.0[start].jf = 8;
    }

    fn deny_dumpable_changes(&mut self) {
        let start = self.1;
        self.push(JEQ, 0, 0, libc::SYS_prctl as u32);
        self.push(LOAD, 0, 0, 16);
        self.push(JEQ, 0, 1, libc::PR_SET_DUMPABLE as u32);
        self.push(RET, 0, 0, DENY);
        self.push(JEQ, 0, 1, libc::PR_SET_PTRACER as u32);
        self.push(RET, 0, 0, DENY);
        self.0[start].jf = 5;
    }
}

fn deny_namespace_clone(filter: &mut Program) {
    let start = filter.1;
    filter.push(JEQ, 0, 0, libc::SYS_clone as u32);
    filter.push(LOAD, 0, 0, 16);
    filter.push(JSET, 0, 1, 0x7e02_0000);
    filter.push(RET, 0, 0, DENY);
    filter.push(LOAD, 0, 0, 0);
    filter.push(RET, 0, 0, ALLOW);
    filter.0[start].jf = 5;
}

fn namespace_syscalls() -> [libc::c_long; 11] {
    [
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_mount_setattr,
    ]
}

fn kernel_control_syscalls() -> [libc::c_long; 23] {
    [
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        libc::SYS_pidfd_getfd,
        libc::SYS_bpf,
        libc::SYS_perf_event_open,
        libc::SYS_keyctl,
        libc::SYS_add_key,
        libc::SYS_request_key,
        libc::SYS_open_by_handle_at,
        libc::SYS_name_to_handle_at,
        libc::SYS_userfaultfd,
        libc::SYS_kcmp,
        libc::SYS_fanotify_init,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_reboot,
        libc::SYS_swapon,
        libc::SYS_swapoff,
    ]
}

fn audit_arch() -> Option<u32> {
    match std::env::consts::ARCH {
        "x86_64" => Some(0xc000_003e),
        "aarch64" => Some(0xc000_00b7),
        "x86" => Some(0x4000_0003),
        "arm" => Some(0x4000_0028),
        "riscv64" => Some(0xc000_00f3),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{PROGRAM_CAPACITY, audit_arch, build};

    #[test]
    fn worst_case_composite_network_none_program_fits_capacity() {
        let arch = audit_arch().expect("test host has an audited architecture");
        let program = build(arch, true, true);
        assert!(
            program.instruction_count() <= PROGRAM_CAPACITY,
            "seccomp program overflow: {} instructions exceed capacity {PROGRAM_CAPACITY}",
            program.instruction_count()
        );
    }
}
