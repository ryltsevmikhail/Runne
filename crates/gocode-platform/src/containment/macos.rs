//! macOS containment — blocked by missing Developer ID signing identity.
//!
//! Platform-specific OS APIs require `unsafe`; all unsafe blocks are isolated
//! in this module with safety comments.
#![allow(unsafe_code)]

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

/// Недоступный до появления подписанного helper бэкенд macOS containment.
pub struct MacOsContainment;

unsafe extern "C" {
    /// sandbox_init применяет Seatbelt profile к текущему процессу.
    /// Возвращает 0 при успехе, -1 при ошибке.
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;
}

/// Проверяет, можем ли мы загрузить libsandbox и применить
/// минимальный Seatbelt profile в дочернем процессе.
///
/// Это не production qualification — только проверка доступности API.
pub fn probe_sandbox_api() -> bool {
    // Минимальный profile: разрешаем всё (allow default).
    // Если sandbox_init успешен, API доступно.
    let profile = "(version 1)\n(debug deny)\n(allow default)\n\0";

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return false;
    }
    if pid == 0 {
        let mut errmsg: *mut libc::c_char = std::ptr::null_mut();
        let ret = unsafe { sandbox_init(profile.as_ptr() as *const libc::c_char, 0, &mut errmsg) };
        // Не освобождаем errmsg, так как дочерний процесс завершается.
        unsafe { libc::exit(if ret == 0 { 0 } else { 1 }) };
    }

    let mut status = 0;
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    waited == pid && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0
}

impl MacOsContainment {
    /// Не предоставляет permit без сертифицированного native backend Phase 6B.
    pub fn attest(
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> Result<AttestationVerdict, ContainmentError> {
        let _ = (request, certificate, probes);
        Err(ContainmentError::BackendUnavailable)
    }

    /// Проверяет sandbox API, но production-бэкенд появится только после
    /// проверки signed helper с Developer ID.
    pub fn probe() -> Result<Self, ContainmentError> {
        // Реальный probe sandbox API выполняется, но containment backend
        // остаётся недоступен до завершения Phase 6B macOS.
        let _ = probe_sandbox_api();
        Err(ContainmentError::BackendUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_api_probe_reports_availability() {
        // На macOS с libsandbox должен вернуться true.
        // Этот тест собирается только под cfg(target_os = \"macos\").
        let available = probe_sandbox_api();
        assert!(
            available,
            "sandbox API should be available on macOS; ad-hoc/test mode only"
        );
    }
}
