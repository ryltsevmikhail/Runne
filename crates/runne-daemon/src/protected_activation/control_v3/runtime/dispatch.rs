// Split from `runtime.rs` to honor the 300-line source limit; included
// right after the runtime state in the same module scope.

pub(crate) struct V3EnrollmentDispatch {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) round_profile: Option<super::round::RoundProfile>,
    pub(super) control: Option<
        Arc<
            crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
        >,
    >,
    #[cfg_attr(
        not(all(target_os = "macos", target_arch = "aarch64")),
        allow(dead_code)
    )]
    pub(super) rendezvous:
        crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous,
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    pub(super) installed_facts:
        Option<runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(super) qualification_verifier:
        Option<runne_native_qualification::QualificationAdmissionVerifier>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(super) qualification_clock: Option<super::QualificationClock>,
    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(super) qualification_verified: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl V3EnrollmentDispatch {
    pub(crate) const fn new(
        control: Option<
            Arc<
                crate::application::provider_credential_enrollment::DaemonProviderCredentialEnrollmentControl,
            >,
        >,
        rendezvous: crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous,
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))] installed_facts: Option<
            runne_platform_desktop::VerifiedInstalledEnrollmentMeasurementFacts,
        >,
    ) -> Self {
        Self {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            round_profile: None,
            control,
            rendezvous,
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            installed_facts,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            qualification_verifier: None,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            qualification_clock: None,
            #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
            qualification_verified: None,
        }
    }

    #[cfg(all(test, target_os = "macos", target_arch = "aarch64"))]
    pub(crate) fn with_test_qualification(
        mut self,
        verifier: runne_native_qualification::QualificationAdmissionVerifier,
        clock: super::QualificationClock,
        verified: Arc<std::sync::atomic::AtomicUsize>,
    ) -> Self {
        self.qualification_verifier = Some(verifier);
        self.qualification_clock = Some(clock);
        self.qualification_verified = Some(verified);
        self
    }
}
