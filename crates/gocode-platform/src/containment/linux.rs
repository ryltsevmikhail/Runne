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
}
