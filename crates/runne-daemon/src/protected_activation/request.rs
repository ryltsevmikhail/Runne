#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]

use super::*;

/// Validated protected launch retained only by the daemon native host.
#[cfg(any(unix, windows))]
pub(super) enum DaemonLaunchRequest {
    V1(ProtectedLaunchRequestV1),
    V2(ProtectedLaunchRequestV2),
    V3(ProtectedCredentialEnrollmentLaunchRequestV3),
}

/// Opaque daemon authority, minted only by a future native verifier.
///
/// It is move-only and has no production constructor: an unverified release
/// tuple, peer, or rendezvous cannot select V3 enrollment.
pub(crate) struct VerifiedDaemonEnrollmentLaunchAuthority {
    provider: ProviderActivationBindingV1,
    binding: Box<ProtectedCredentialEnrollmentLaunchBindingV1>,
    prelude: Box<runne_api::DaemonEnrollmentLaunchPreludeV1>,
}

impl VerifiedDaemonEnrollmentLaunchAuthority {
    #[cfg(all(
        target_os = "macos",
        target_arch = "aarch64",
        feature = "desktop-protected"
    ))]
    pub(super) fn from_verified(
        evidence: super::enrollment_transition_v2_v3::VerifiedV2EnrollmentEvidence,
    ) -> Self {
        let (provider, binding, prelude) = evidence.into_authority_parts();
        Self {
            provider,
            binding: Box::new(binding),
            prelude: Box::new(prelude),
        }
    }
}

#[cfg(all(test, unix))]
impl VerifiedDaemonEnrollmentLaunchAuthority {
    pub(super) fn test_only(
        provider: ProviderActivationBindingV1,
        binding: ProtectedCredentialEnrollmentLaunchBindingV1,
        prelude: runne_api::DaemonEnrollmentLaunchPreludeV1,
    ) -> Self {
        Self {
            provider,
            binding: Box::new(binding),
            prelude: Box::new(prelude),
        }
    }
}

/// Independently verified native launch shape; never derived from the frame.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) enum DaemonLaunchProtocolExpectation {
    Baseline,
    Enrollment(VerifiedDaemonEnrollmentLaunchAuthority),
}

impl DaemonLaunchProtocolExpectation {
    pub(crate) const fn baseline() -> Self {
        Self::Baseline
    }

    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub(super) fn enrollment(authority: VerifiedDaemonEnrollmentLaunchAuthority) -> Self {
        Self::Enrollment(authority)
    }
}

#[cfg(any(unix, windows))]
impl DaemonLaunchRequest {
    pub(super) fn decode_frame(frame: &[u8]) -> Result<Self, LaunchAuthorityError> {
        if let Ok(request) = ProtectedCredentialEnrollmentLaunchRequestV3::decode_frame(frame) {
            return Ok(Self::V3(request));
        }
        if let Ok(request) = ProtectedLaunchRequestV2::decode_frame(frame) {
            return Ok(Self::V2(request));
        }
        ProtectedLaunchRequestV1::decode_frame(frame)
            .map(Self::V1)
            .map_err(|_| LaunchAuthorityError::InvalidContract)
    }

    /// Legacy-only V1 view. V3 has no compatibility projection.
    pub(super) fn compatibility(&self) -> Option<&ProtectedLaunchRequestV1> {
        match self {
            Self::V1(request) => Some(request),
            Self::V2(request) => Some(request.compatibility_request()),
            Self::V3(_) => None,
        }
    }

    pub(super) fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
    ) -> Result<ProviderActivation, LaunchAuthorityError> {
        self.validate_for_protocol(
            now_unix_millis,
            expected,
            DaemonLaunchProtocolExpectation::baseline(),
        )
    }

    pub(super) fn validate_for_protocol(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
        protocol: DaemonLaunchProtocolExpectation,
    ) -> Result<ProviderActivation, LaunchAuthorityError> {
        match self {
            Self::V1(request) => {
                if !matches!(protocol, DaemonLaunchProtocolExpectation::Baseline) {
                    return Err(LaunchAuthorityError::InvalidContract);
                }
                request.validate(now_unix_millis, expected)?;
                request.validate_provider_mode(ProviderActivationModeV1::DeterministicV1)?;
                Ok(ProviderActivation::deterministic_v1())
            }
            Self::V2(request) => {
                if !matches!(protocol, DaemonLaunchProtocolExpectation::Baseline) {
                    return Err(LaunchAuthorityError::InvalidContract);
                }
                let activation =
                    ProviderActivation::from_binding(request.provider_binding().clone());
                request.validate(now_unix_millis, expected, activation.binding())?;
                Ok(activation)
            }
            Self::V3(request) => {
                let DaemonLaunchProtocolExpectation::Enrollment(authority) = protocol else {
                    return Err(LaunchAuthorityError::InvalidContract);
                };
                request.validate(
                    now_unix_millis,
                    expected,
                    &authority.provider,
                    &authority.binding,
                )?;
                if request.launch_authority_id() != authority.prelude.launch_authority_id()
                    || request.desktop_host_instance_id()
                        != authority.prelude.desktop_host_instance_id()
                {
                    return Err(LaunchAuthorityError::OwnershipMismatch);
                }
                authority.prelude.validate_freshness(now_unix_millis)?;
                let keys = request.derive_keys();
                let actual =
                    runne_api::CredentialBrokerTransferAuthenticator::from_protected_activation(
                        &keys,
                    )
                    .enrollment_launch_commitment(&authority.prelude);
                if actual != *authority.binding.broker_transfer_commitment() {
                    return Err(LaunchAuthorityError::OwnershipMismatch);
                }
                Ok(ProviderActivation::from_binding(authority.provider.clone()))
            }
        }
    }

    pub(super) fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        match self {
            Self::V1(request) => request.derive_keys_and_forget(),
            Self::V2(request) => request.derive_keys_and_forget(),
            Self::V3(request) => request.derive_keys_and_forget(),
        }
    }

    pub(super) fn validate_freshness(
        &self,
        now_unix_millis: u64,
    ) -> Result<(), LaunchAuthorityError> {
        match self {
            Self::V1(request) => request.validate_freshness(now_unix_millis),
            Self::V2(request) => request.validate_freshness(now_unix_millis),
            Self::V3(request) => request.validate_freshness(now_unix_millis),
        }
    }

    pub(super) fn launch_authority_id(&self) -> [u8; 16] {
        match self {
            Self::V1(request) => request.launch_authority_id(),
            Self::V2(request) => request.compatibility_request().launch_authority_id(),
            Self::V3(request) => request.launch_authority_id(),
        }
    }

    pub(super) fn desktop_host_instance_id(&self) -> [u8; 16] {
        match self {
            Self::V1(request) => request.desktop_host_instance_id(),
            Self::V2(request) => request.compatibility_request().desktop_host_instance_id(),
            Self::V3(request) => request.desktop_host_instance_id(),
        }
    }

    pub(super) fn runtime_root(&self) -> &std::path::Path {
        match self {
            Self::V1(request) => request.runtime_root(),
            Self::V2(request) => request.compatibility_request().runtime_root(),
            Self::V3(request) => request.runtime_root(),
        }
    }

    pub(super) fn activation_disposition(&self) -> &ActivationDispositionV1 {
        match self {
            Self::V1(request) => request.activation_disposition(),
            Self::V2(request) => request.compatibility_request().activation_disposition(),
            Self::V3(request) => request.activation_disposition(),
        }
    }
}
