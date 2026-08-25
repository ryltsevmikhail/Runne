#![cfg_attr(not(feature = "desktop-protected"), allow(dead_code))]

use super::*;

/// Validated protected launch retained only by the daemon native host.
#[cfg(any(unix, windows))]
pub(super) enum DaemonLaunchRequest {
    V1(ProtectedLaunchRequestV1),
    V2(ProtectedLaunchRequestV2),
}

#[cfg(any(unix, windows))]
impl DaemonLaunchRequest {
    pub(super) fn decode_frame(frame: &[u8]) -> Result<Self, LaunchAuthorityError> {
        if let Ok(request) = ProtectedLaunchRequestV2::decode_frame(frame) {
            return Ok(Self::V2(request));
        }
        ProtectedLaunchRequestV1::decode_frame(frame)
            .map(Self::V1)
            .map_err(|_| LaunchAuthorityError::InvalidContract)
    }

    pub(super) const fn compatibility(&self) -> &ProtectedLaunchRequestV1 {
        match self {
            Self::V1(request) => request,
            Self::V2(request) => request.compatibility_request(),
        }
    }

    pub(super) fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
    ) -> Result<ProviderActivation, LaunchAuthorityError> {
        match self {
            Self::V1(request) => {
                request.validate(now_unix_millis, expected)?;
                request.validate_provider_mode(ProviderActivationModeV1::DeterministicV1)?;
                Ok(ProviderActivation::deterministic_v1())
            }
            Self::V2(request) => {
                let activation =
                    ProviderActivation::from_binding(request.provider_binding().clone());
                request.validate(now_unix_millis, expected, activation.binding())?;
                Ok(activation)
            }
        }
    }

    pub(super) fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        match self {
            Self::V1(request) => request.derive_keys_and_forget(),
            Self::V2(request) => request.derive_keys_and_forget(),
        }
    }

    pub(super) fn validate_freshness(
        &self,
        now_unix_millis: u64,
    ) -> Result<(), LaunchAuthorityError> {
        match self {
            Self::V1(request) => request.validate_freshness(now_unix_millis),
            Self::V2(request) => request.validate_freshness(now_unix_millis),
        }
    }
}
