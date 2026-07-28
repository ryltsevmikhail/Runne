//! Windows containment is unavailable until a native backend is certified.

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

/// Недоступный до сертификации native Windows containment бэкенд.
pub struct WindowsContainment;

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

    /// Не публикует неподтверждённые AppContainer или Job Object возможности.
    pub fn probe() -> Result<Self, ContainmentError> {
        Err(ContainmentError::BackendUnavailable)
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    #[cfg(target_os = "windows")]
    #[test]
    fn probe_is_unavailable_until_native_backend_is_certified() {
        assert!(matches!(
            WindowsContainment::probe(),
            Err(ContainmentError::BackendUnavailable)
        ));
    }
}
