//! Windows containment is unavailable until a native backend is certified.
//!
//! Platform-specific OS APIs require `unsafe`; all unsafe blocks are isolated
//! in this module with safety comments.
#![allow(unsafe_code)]

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

/// Недоступный до сертификации native Windows containment бэкенд.
pub struct WindowsContainment;

#[cfg(target_os = "windows")]
#[allow(dead_code, non_camel_case_types, clippy::upper_case_acronyms)]
mod winapi {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;
    pub type DWORD = u32;
    pub type LPSECURITY_ATTRIBUTES = *mut c_void;
    pub type LPCWSTR = *const u16;

    pub const NULL_HANDLE: HANDLE = std::ptr::null_mut();

    unsafe extern "system" {
        pub fn CreateJobObjectW(lpJobAttributes: LPSECURITY_ATTRIBUTES, lpName: LPCWSTR) -> HANDLE;
        pub fn CloseHandle(hObject: HANDLE) -> BOOL;
        pub fn GetLastError() -> DWORD;
    }
}

/// Проверяет, доступны ли Job Objects в текущей Windows-сессии.
#[cfg(target_os = "windows")]
pub fn probe_job_objects() -> bool {
    use winapi::*;

    unsafe {
        let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
        if job.is_null() {
            return false;
        }
        let closed = CloseHandle(job);
        closed != 0
    }
}

/// На non-Windows платформах Job Objects недоступны.
#[cfg(not(target_os = "windows"))]
pub fn probe_job_objects() -> bool {
    false
}

impl WindowsContainment {
    /// Не предоставляет permit без сертифицированного native backend Phase 6B.
    pub fn attest(
        request: &ContainmentRequest,
        certificate: Option<&NativeCertificate>,
        probes: &[RuntimeProbe],
    ) -> Result<AttestationVerdict, ContainmentError> {
        let _ = (request, certificate, probes);
        Err(ContainmentError::BackendUnavailable)
    }

    /// Проверяет Job Objects, но не публикует неподтверждённые AppContainer возможности.
    pub fn probe() -> Result<Self, ContainmentError> {
        // Реальный probe Job Objects выполняется, но containment backend
        // остаётся недоступен до завершения Phase 6B Windows.
        let _ = probe_job_objects();
        Err(ContainmentError::BackendUnavailable)
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[test]
    fn probe_is_unavailable_until_native_backend_is_certified() {
        assert!(matches!(
            WindowsContainment::probe(),
            Err(ContainmentError::BackendUnavailable)
        ));
    }

    #[test]
    fn job_objects_api_is_available() {
        assert!(
            probe_job_objects(),
            "Job Objects API should be available on Windows"
        );
    }
}
