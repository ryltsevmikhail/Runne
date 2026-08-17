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
        // Реальный probe Landlock ABI выполняется, но containment backend
        // остаётся недоступен до завершения Phase 6B.
        let _ = probe_landlock_abi();
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
}
