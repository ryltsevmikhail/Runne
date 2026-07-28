//! macOS containment — blocked by missing Developer ID signing identity.

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

/// Недоступный до появления подписанного helper бэкенд macOS containment.
pub struct MacOsContainment;

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

    /// Сообщить, что production-бэкенд macOS пока недоступен.
    pub fn probe() -> Result<Self, ContainmentError> {
        // Production-бэкенд появится после проверки signed helper с Developer ID.
        Err(ContainmentError::BackendUnavailable)
    }
}
