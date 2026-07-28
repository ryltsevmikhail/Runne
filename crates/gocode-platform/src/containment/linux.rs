//! Linux containment is unavailable until a native backend is certified.

use super::{
    AttestationVerdict, ContainmentError, ContainmentRequest, NativeCertificate, RuntimeProbe,
};

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

    /// Не публикует неподтверждённые Landlock, seccomp или cgroups возможности.
    pub fn probe() -> Result<Self, ContainmentError> {
        Err(ContainmentError::BackendUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_is_unavailable_until_native_backend_is_certified() {
        assert!(matches!(
            LinuxContainment::probe(),
            Err(ContainmentError::BackendUnavailable)
        ));
    }
}
