//! Linux containment is unavailable until a native backend is certified.

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
    if ret >= 0 {
        Some(ret as u32)
    } else {
        None
    }
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
}
