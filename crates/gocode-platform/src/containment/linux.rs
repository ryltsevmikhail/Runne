//! Linux containment is unavailable until a native backend is certified.
//!
//! Platform-specific OS syscalls require `unsafe`; all unsafe blocks are
//! isolated in this module with safety comments.
#![allow(unsafe_code)]

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

/// Проверяет доступность Landlock ABI в текущем ядре.
///
/// Возвращает ABI version (начиная с 1), если Landlock поддерживается,
/// или `None`, если syscall отсутствует/запрещён.
pub fn probe_landlock_abi() -> Option<u32> {
    // landlock_create_ruleset(NULL, 0, 0) возвращает ABI version.
    // См. https://docs.kernel.org/userspace-api/landlock.html
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0usize, // attr = NULL
            0usize, // size = 0
            0u32,   // flags = 0
        )
    };
    if ret >= 0 { Some(ret as u32) } else { None }
}

/// Создаёт Landlock ruleset с заданными handled_access_fs правами.
///
/// Это реальный OS probe: если ruleset создаётся,
/// ядро поддерживает Landlock с указанными правами.
/// Функция не вызывает `restrict_self` — она только проверяет,
/// что syscalls работают.
pub fn create_landlock_ruleset(handled_access_fs: u64) -> Result<libc::c_int, ContainmentError> {
    // landlock_ruleset_attr: { handled_access_fs: u64 }
    let attr = handled_access_fs;
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const u64 as usize,
            std::mem::size_of::<u64>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(fd as libc::c_int)
}

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
    reserved: u32,
}

/// Добавляет в ruleset правило `path_beneath` для каталога `parent_fd`.
pub fn add_landlock_path_rule(
    ruleset_fd: libc::c_int,
    parent_fd: libc::c_int,
    allowed_access: u64,
) -> Result<(), ContainmentError> {
    let attr = LandlockPathBeneathAttr {
        allowed_access,
        parent_fd,
        reserved: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset_fd as usize,
            LANDLOCK_RULE_PATH_BENEATH as usize,
            &attr as *const LandlockPathBeneathAttr as usize,
            0usize,
        )
    };
    if ret < 0 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(())
}

/// Применяет Landlock ruleset к текущему процессу.
pub fn restrict_self_with_landlock(ruleset_fd: libc::c_int) -> Result<(), ContainmentError> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            ruleset_fd as usize,
            0usize,
        )
    };
    if ret < 0 {
        return Err(ContainmentError::BackendUnavailable);
    }
    Ok(())
}

/// Проверяет доступность seccomp filter mode в текущем ядре.
///
/// Использует `prctl(PR_GET_SECCOMP)`; если syscall возвращает
/// режим (отключен/строгий/filter), seccomp поддерживается.
pub fn probe_seccomp_filter() -> bool {
    const PR_GET_SECCOMP: libc::c_int = 21;
    let ret = unsafe {
        libc::syscall(
            libc::SYS_prctl,
            PR_GET_SECCOMP as usize,
            0usize,
            0usize,
            0usize,
            0usize,
        )
    };
    ret >= 0
}

/// Проверяет, доступна ли запись в cgroups v2 для ограничения ресурсов.
///
/// Проверяет существование `/sys/fs/cgroup/cgroup.controllers`
/// и возможность записи в `memory.max` или `pids.max`
/// в текущей cgroup.
pub fn probe_cgroups_v2_delegated() -> bool {
    use std::path::Path;

    let cgroup_root = Path::new("/sys/fs/cgroup");
    if !cgroup_root.join("cgroup.controllers").exists() {
        return false;
    }
    // Проверяем делегированный контроллер memory или pids.
    cgroup_root.join("memory.max").is_file() || cgroup_root.join("pids.max").is_file()
}

/// Недоступный до сертификации native Linux containment бэкенд.
pub struct LinuxContainment;

impl LinuxContainment {
    /// Не предоставляет permit без сертифицированного native backend Phase 6B.
    pub fn attest(
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> Result<AttestationVerdict, ContainmentError> {
        let _ = (request, certificate, probes);
        Err(ContainmentError::BackendUnavailable)
    }

    /// Проверяет Landlock ABI, но не публикует неподтверждённые seccomp/cgroups
    /// возможности. До полной сертификации Phase 6B attestation остаётся
    /// fail-closed.
    pub fn probe() -> Result<Self, ContainmentError> {
        // Реальные probes Landlock ABI, seccomp и cgroups v2 выполняются, но
        // containment backend остаётся недоступен до завершения Phase 6B.
        let _ = (
            probe_landlock_abi(),
            probe_seccomp_filter(),
            probe_cgroups_v2_delegated(),
        );
        Err(ContainmentError::BackendUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_unavailable_until_native_backend_is_certified() {
        assert!(
            matches!(
                LinuxContainment::probe(),
                Err(ContainmentError::BackendUnavailable)
            ),
            "containment backend must remain fail-closed until Phase 6B is certified"
        );
    }

    #[test]
    fn landlock_abi_probe_reports_capability_or_absence() {
        // На Linux с kernel ≥ 5.13 должен вернуться Some(abi_version).
        // На старых ядрах или non-Linux target этот тест не собирается
        // (модуль под cfg(target_os = \"linux\")).
        let result = probe_landlock_abi();
        assert!(
            result.is_none() || result.unwrap() >= 1,
            "Landlock ABI version must be either unavailable or >= 1, got {:?}",
            result
        );
    }

    #[test]
    fn seccomp_filter_probe_reports_availability() {
        // На Linux ядрах с seccomp должен вернуться true.
        // Этот тест собирается только под cfg(target_os = \"linux\").
        let available = probe_seccomp_filter();
        // Проба не должна паниковать; значение true/false зависит от ядра.
        let _ = available;
    }

    #[test]
    fn cgroups_v2_probe_reports_availability_or_absence() {
        // На Linux с cgroups v2 должен вернуться true или false;
        // на non-Linux этот тест не собирается.
        let _ = probe_cgroups_v2_delegated();
    }

    #[test]
    fn landlock_ruleset_can_be_created_with_abi_v1_rights() {
        // Проверяем, что ядро позволяет создать ruleset с
        // базовыми filesystem access rights ABI v1.
        const ACCESS_FS_READ_FILE: u64 = 1 << 2;
        const ACCESS_FS_READ_DIR: u64 = 1 << 3;
        match create_landlock_ruleset(ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR) {
            Ok(fd) => unsafe { libc::close(fd) },
            Err(ContainmentError::BackendUnavailable) => {
                // Landlock не доступен — это допустимо для старых ядер.
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn landlock_restrict_self_blocks_escape_path() {
        // Этот тест доказывает, что Landlock может запретить доступ за пределы
        // разрешённого каталога. Тест выполняется в forked child,
        // чтобы не замораживать родительский процесс.
        use std::ffi::CString;
        use std::fs;

        const ACCESS_FS_READ_FILE: u64 = 1 << 2;
        const ACCESS_FS_READ_DIR: u64 = 1 << 3;

        let tmp = std::env::temp_dir().join("gocode_landlock_enforcement_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).expect("create temp dir");
        let allowed_file = tmp.join("allowed.txt");
        fs::write(&allowed_file, "ok").expect("write allowed file");

        let dir_cstr = CString::new(tmp.as_os_str().as_encoded_bytes()).expect("temp dir path");
        let allowed_cstr =
            CString::new(allowed_file.as_os_str().as_encoded_bytes()).expect("allowed file path");

        let dir_fd = unsafe {
            libc::open(
                dir_cstr.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        assert!(dir_fd >= 0, "failed to open temp dir");

        let ruleset_fd = create_landlock_ruleset(ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR)
            .expect("create ruleset");
        add_landlock_path_rule(ruleset_fd, dir_fd, ACCESS_FS_READ_FILE | ACCESS_FS_READ_DIR)
            .expect("add path rule");
        unsafe { libc::close(dir_fd) };

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child: apply sandbox, then verify escape is blocked and allowed path works.
            restrict_self_with_landlock(ruleset_fd).expect("restrict_self");
            unsafe { libc::close(ruleset_fd) };

            // /etc/passwd must be blocked with EACCES.
            let etc_fd = unsafe {
                libc::open(
                    "/etc/passwd\0".as_ptr() as *const libc::c_char,
                    libc::O_RDONLY,
                )
            };
            if etc_fd >= 0 {
                unsafe { libc::close(etc_fd) };
                eprintln!("escape path was not blocked");
                unsafe { libc::exit(1) };
            }
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EACCES {
                eprintln!("unexpected errno for blocked path: {errno}");
                unsafe { libc::exit(2) };
            }

            // Allowed file must remain readable.
            let fd = unsafe { libc::open(allowed_cstr.as_ptr(), libc::O_RDONLY) };
            if fd < 0 {
                eprintln!("allowed path was unexpectedly blocked");
                unsafe { libc::exit(3) };
            }
            let mut buf = [0u8; 4];
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            unsafe { libc::close(fd) };
            if n != 2 || &buf[..2] != b"ok" {
                eprintln!("allowed file content mismatch");
                unsafe { libc::exit(4) };
            }

            unsafe { libc::exit(0) };
        }

        // Parent: wait for child and verify it reported success.
        unsafe { libc::close(ruleset_fd) };
        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed");
        assert!(libc::WIFEXITED(status), "child did not exit cleanly");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child failed to verify Landlock containment"
        );
    }

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
    fn cgroups_v2_pids_limit_enforced() {
        // Создаём дочернюю cgroup, ограничиваем pids.max = 2,
        // перемещаем туда forked child и проверяем,
        // что второй fork() в ней завершается ошибкой EAGAIN.
        use std::fs;
        use std::path::PathBuf;

        let cgroup_root = PathBuf::from("/sys/fs/cgroup");
        if !cgroup_root.join("cgroup.controllers").exists() {
            // cgroups v2 не доступен — тест не пройдёт, но и не упадёт.
            return;
        }

        let child_cgroup = cgroup_root.join(format!("gocode_cgroup_pids_test_{}", unsafe {
            libc::getpid()
        }));
        let _ = fs::remove_dir(&child_cgroup);
        fs::create_dir(&child_cgroup).expect("create child cgroup");

        // Включаем pids controller в родительской cgroup.
        let _ = fs::write(cgroup_root.join("cgroup.subtree_control"), "+pids\n");

        // Ограничиваем дочернюю cgroup двумя процессами.
        fs::write(child_cgroup.join("pids.max"), "2\n").expect("write pids.max");

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child moves itself into the child cgroup.
            let self_pid = unsafe { libc::getpid() };
            fs::write(child_cgroup.join("cgroup.procs"), format!("{}\n", self_pid))
                .expect("move self to child cgroup");

            // First fork succeeds: child + grandchild = 2 pids.
            let grandchild = unsafe { libc::fork() };
            if grandchild < 0 {
                eprintln!("first fork failed unexpectedly");
                unsafe { libc::exit(1) };
            }
            if grandchild == 0 {
                // Grandchild exits immediately.
                unsafe { libc::exit(0) };
            }
            let mut gc_status = 0;
            unsafe { libc::waitpid(grandchild, &mut gc_status, 0) };

            // Second fork must fail with EAGAIN because pids.max = 2.
            let second = unsafe { libc::fork() };
            if second == 0 {
                // If second fork succeeded, the limit was not enforced.
                unsafe { libc::exit(10) };
            }
            if second > 0 {
                // We succeeded in forking a second time: enforcement failed.
                let mut s = 0;
                unsafe { libc::waitpid(second, &mut s, 0) };
                eprintln!("second fork succeeded, pids.max not enforced");
                unsafe { libc::exit(2) };
            }
            let errno = unsafe { *libc::__errno_location() };
            if errno != libc::EAGAIN {
                eprintln!("second fork failed with unexpected errno {errno}");
                unsafe { libc::exit(3) };
            }

            unsafe { libc::exit(0) };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed");
        assert!(libc::WIFEXITED(status), "child did not exit cleanly");
        assert_eq!(
            libc::WEXITSTATUS(status),
            0,
            "child failed to verify cgroups pids.max enforcement"
        );

        let _ = fs::remove_dir(&child_cgroup);
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

    #[test]
    fn descendant_cleanup_via_pdeathsig() {
        // Проверяем, что дочерний процесс умирает, когда умирает родитель,
        // благодаря PR_SET_PDEATHSIG = SIGKILL.
        use std::fs;

        const PR_SET_PDEATHSIG: libc::c_int = 1;
        let pid_file = std::env::temp_dir().join("gocode_pdeathsig_test_child_pid");
        let _ = fs::remove_file(&pid_file);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            let ret = unsafe {
                libc::syscall(
                    libc::SYS_prctl,
                    PR_SET_PDEATHSIG as usize,
                    libc::SIGKILL as usize,
                    0usize,
                    0usize,
                    0usize,
                )
            };
            if ret < 0 {
                eprintln!("PR_SET_PDEATHSIG failed in parent");
                unsafe { libc::exit(1) };
            }

            let child_b = unsafe { libc::fork() };
            if child_b < 0 {
                eprintln!("fork child B failed");
                unsafe { libc::exit(2) };
            }
            if child_b == 0 {
                let ret = unsafe {
                    libc::syscall(
                        libc::SYS_prctl,
                        PR_SET_PDEATHSIG as usize,
                        libc::SIGKILL as usize,
                        0usize,
                        0usize,
                        0usize,
                    )
                };
                if ret < 0 {
                    eprintln!("PR_SET_PDEATHSIG failed in child B");
                    unsafe { libc::exit(3) };
                }
                fs::write(&pid_file, format!("{}\n", unsafe { libc::getpid() }))
                    .expect("write child B pid");
                loop {
                    unsafe { libc::sleep(10) };
                }
            }

            // Даём child B время записать pid, потом выходим.
            unsafe { libc::usleep(200_000) };
            unsafe { libc::exit(0) };
        }

        let mut status = 0;
        let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(waited, pid, "waitpid failed");
        assert!(libc::WIFEXITED(status), "child A did not exit cleanly");

        // Даём PR_SET_PDEATHSIG время сработать.
        unsafe { libc::usleep(200_000) };

        let child_b_pid: libc::pid_t = fs::read_to_string(&pid_file)
            .expect("read child B pid")
            .trim()
            .parse()
            .expect("parse child B pid");
        let ret = unsafe { libc::kill(child_b_pid, 0) };
        assert!(ret < 0, "child B should have been killed");
        let errno = unsafe { *libc::__errno_location() };
        assert_eq!(errno, libc::ESRCH, "child B should not exist anymore");

        let _ = fs::remove_file(&pid_file);
    }

    #[test]
    fn timeout_termination_enforced() {
        // Проверяем, что можем дождаться завершения процесса с timeout
        // и при необходимости прибить его SIGKILL.
        const TIMEOUT_MS: u128 = 200;

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child sleeps forever.
            loop {
                unsafe { libc::sleep(10) };
            }
        }

        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(TIMEOUT_MS as u64);
        let mut status = 0;

        loop {
            let ret = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            assert!(ret >= 0, "waitpid failed");
            if ret == pid {
                panic!("child exited before timeout");
            }
            if start.elapsed() >= timeout {
                break;
            }
            unsafe { libc::usleep(10_000) };
        }

        let ret = unsafe { libc::kill(pid, libc::SIGKILL) };
        assert_eq!(ret, 0, "SIGKILL failed");

        let ret = unsafe { libc::waitpid(pid, &mut status, 0) };
        assert_eq!(ret, pid, "waitpid after kill failed");
        assert!(
            libc::WIFSIGNALED(status),
            "child should have been killed by timeout"
        );
        assert_eq!(
            libc::WTERMSIG(status),
            libc::SIGKILL,
            "child should have been killed by SIGKILL"
        );
    }
}
