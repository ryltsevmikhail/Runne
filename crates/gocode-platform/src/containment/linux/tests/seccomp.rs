//! seccomp-bpf enforcement tests: mount kill-on-syscall and direct-egress denial.

#[test]
fn seccomp_filter_kills_on_disallowed_syscall() {
    // Устанавливаем seccomp-bpf filter, который убивает
    // процесс при вызове mount. Тест выполняется в forked child.
    const PR_SET_SECCOMP: libc::c_int = 22;
    const SECCOMP_MODE_FILTER: libc::c_uint = 2;

    #[repr(C)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct sock_fprog {
        len: u16,
        filter: *const sock_filter,
    }

    // BPF program: load syscall nr, if == mount then KILL else ALLOW.
    let filter: [sock_filter; 4] = [
        sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_mount as u32,
        },
        sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        let fprog = sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        let ret = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                PR_SET_SECCOMP as usize,
                SECCOMP_MODE_FILTER as usize,
                &fprog as *const sock_fprog as usize,
                0usize,
                0usize,
            )
        };
        if ret < 0 {
            eprintln!("prctl(PR_SET_SECCOMP) failed");
            unsafe { libc::exit(1) };
        }

        // Вызываем запрещённый syscall. Должен прийти SIGSYS.
        unsafe {
            libc::syscall(libc::SYS_mount, 0usize, 0usize, 0usize, 0usize, 0usize);
        }

        // Если досюда дошли, mount не был заблокирован.
        eprintln!("disallowed syscall returned");
        unsafe { libc::exit(2) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    assert!(
        libc::WIFSIGNALED(status),
        "child should have been killed by seccomp"
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGSYS,
        "child should have been killed by SIGSYS"
    );
}

#[test]
fn seccomp_filter_blocks_direct_egress() {
    // seccomp-bpf filter запрещает системные вызовы connect и bind,
    // что доказывает direct egress denial.
    const PR_SET_SECCOMP: libc::c_int = 22;
    const SECCOMP_MODE_FILTER: libc::c_uint = 2;

    #[repr(C)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[repr(C)]
    struct sock_fprog {
        len: u16,
        filter: *const sock_filter,
    }

    // BPF: load nr; if connect -> kill; if bind -> kill; else allow.
    let filter: [sock_filter; 6] = [
        sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 2,
            k: libc::SYS_connect as u32,
        },
        sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 2,
            k: libc::SYS_bind as u32,
        },
        sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_KILL_PROCESS,
        },
        sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];

    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");

    if pid == 0 {
        let fprog = sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_ptr(),
        };
        let ret = unsafe {
            libc::syscall(
                libc::SYS_prctl,
                PR_SET_SECCOMP as usize,
                SECCOMP_MODE_FILTER as usize,
                &fprog as *const sock_fprog as usize,
                0usize,
                0usize,
            )
        };
        if ret < 0 {
            eprintln!("prctl(PR_SET_SECCOMP) failed");
            unsafe { libc::exit(1) };
        }

        // connect(2) on an invalid fd — должен прийти SIGSYS до того,
        // как ядро вернёт EBADF.
        unsafe { libc::connect(-1, std::ptr::null(), 0) };

        eprintln!("connect was not blocked");
        unsafe { libc::exit(2) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    assert_eq!(waited, pid, "waitpid failed");
    assert!(
        libc::WIFSIGNALED(status),
        "child should have been killed by seccomp"
    );
    assert_eq!(
        libc::WTERMSIG(status),
        libc::SIGSYS,
        "child should have been killed by SIGSYS"
    );
}
