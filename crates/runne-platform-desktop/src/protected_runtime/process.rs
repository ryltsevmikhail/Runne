
#[cfg(any(unix, windows))]
enum DesktopLaunchRequest {
    V1(ProtectedLaunchRequestV1),
    V2(ProtectedLaunchRequestV2),
    #[allow(dead_code)] // Minted only by a future verified native qualification seam.
    V3(runne_api::ProtectedCredentialEnrollmentLaunchRequestV3),
}

#[cfg(any(unix, windows))]
impl DesktopLaunchRequest {
    const fn compatibility(&self) -> Option<&ProtectedLaunchRequestV1> {
        match self {
            Self::V1(request) => Some(request),
            Self::V2(request) => Some(request.compatibility_request()),
            Self::V3(_) => None,
        }
    }

    const fn executable(&self) -> &ExecutableIdentityV1 {
        match self {
            Self::V1(request) => request.executable(),
            Self::V2(request) => request.executable(),
            Self::V3(request) => request.executable(),
        }
    }

    const fn activation_disposition(&self) -> &ActivationDispositionV1 {
        match self {
            Self::V1(request) => request.activation_disposition(),
            Self::V2(request) => request.activation_disposition(),
            Self::V3(request) => request.activation_disposition(),
        }
    }

    fn encode_frame(&self) -> Result<Vec<u8>, LaunchAuthorityError> {
        match self {
            Self::V1(request) => request.encode_frame(),
            Self::V2(request) => request.encode_frame(),
            Self::V3(request) => request.encode_frame(),
        }
        .map_err(|_| LaunchAuthorityError::InvalidContract)
    }

    fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        match self {
            Self::V1(request) => request.derive_keys_and_forget(),
            Self::V2(request) => request.derive_keys_and_forget(),
            Self::V3(request) => request.derive_keys_and_forget(),
        }
    }

    fn decode_ready(
        &self,
        frame: &[u8],
        keys: &ProtectedActivationKeys,
    ) -> Result<DesktopReady, LaunchAuthorityError> {
        match self {
            Self::V1(request) => {
                let ready = ProtectedReadyV1::decode_frame(frame)
                    .map_err(|_| LaunchAuthorityError::ReadinessProofMismatch)?;
                ready.verify_exact(request, keys)?;
                Ok(DesktopReady::V1(ready))
            }
            Self::V2(request) => {
                let ready = ProtectedReadyV2::decode_frame(frame)
                    .map_err(|_| LaunchAuthorityError::ReadinessProofMismatch)?;
                ready.verify_exact(request, keys)?;
                Ok(DesktopReady::V2(ready))
            }
            Self::V3(request) => {
                let ready = runne_api::ProtectedCredentialEnrollmentReadyV3::decode_frame(frame)
                    .map_err(|_| LaunchAuthorityError::ReadinessProofMismatch)?;
                ready.verify_exact(request, keys)?;
                Ok(DesktopReady::V3(ready))
            }
        }
    }

    fn runtime_profile(
        &self,
        ready: &DesktopReady,
        now_unix_millis: u64,
        keys: &ProtectedActivationKeys,
    ) -> Result<ProtectedBundledRuntimeProfile, LaunchAuthorityError> {
        match (self, ready) {
            (Self::V1(request), DesktopReady::V1(ready)) => {
                ProtectedBundledRuntimeProfile::from_ready(ready, request, keys)
            }
            (Self::V2(request), DesktopReady::V2(ready)) => {
                ProtectedBundledRuntimeProfile::from_ready_v2(ready, request, keys)
            }
            (Self::V3(request), DesktopReady::V3(ready)) => {
                ProtectedBundledRuntimeProfile::from_ready_v3(ready, request, now_unix_millis, keys)
            }
            _ => Err(LaunchAuthorityError::OwnershipMismatch),
        }
    }
}

#[cfg(any(unix, windows))]
enum DesktopReady {
    V1(ProtectedReadyV1),
    V2(ProtectedReadyV2),
    V3(runne_api::ProtectedCredentialEnrollmentReadyV3),
}

#[cfg(any(unix, windows))]
impl DesktopReady {
    const fn stable(&self) -> &StableRuntimeBindingV1 {
        match self {
            Self::V1(ready) => ready.stable(),
            Self::V2(ready) => ready.stable(),
            Self::V3(ready) => ready.stable(),
        }
    }

    /// Returns the authenticated provider readiness disposition for V2, or
    /// `None` for the V1 deterministic protocol which carries no disposition.
    const fn provider_readiness(&self) -> Option<ProviderActivationReadinessV1> {
        match self {
            Self::V1(_) => None,
            Self::V2(ready) => Some(ready.provider_readiness()),
            Self::V3(ready) => Some(ready.provider_readiness()),
        }
    }

    fn into_process_activation(
        self,
        request: DesktopLaunchRequest,
    ) -> Result<ProtectedProcessActivation, ProtectedBundledRuntimeError> {
        match (request, self) {
            (DesktopLaunchRequest::V1(request), Self::V1(ready)) => {
                let owned = ready.owned_launch();
                Ok(ProtectedProcessActivation::V1 {
                    request,
                    ready,
                    owned,
                })
            }
            (DesktopLaunchRequest::V2(request), Self::V2(ready)) => {
                let owned = ready.owned_launch();
                Ok(ProtectedProcessActivation::V2 {
                    request,
                    ready,
                    owned,
                })
            }
            (DesktopLaunchRequest::V3(request), Self::V3(ready)) => {
                let owned = ready.owned_launch();
                Ok(ProtectedProcessActivation::V3 {
                    request,
                    ready,
                    owned,
                })
            }
            _ => Err(ProtectedBundledRuntimeError::InvalidState),
        }
    }
}

const fn provider_readiness_blocks_launch(readiness: ProviderActivationReadinessV1) -> bool {
    !matches!(
        readiness,
        ProviderActivationReadinessV1::Ready
            | ProviderActivationReadinessV1::CredentialMissing
            | ProviderActivationReadinessV1::SecureStoreUnavailable
    )
}

#[cfg(any(unix, windows))]
#[allow(clippy::large_enum_variant)]
enum ProtectedProcessActivation {
    V1 {
        request: ProtectedLaunchRequestV1,
        ready: ProtectedReadyV1,
        owned: ProtectedOwnedLaunchV1,
    },
    V2 {
        request: ProtectedLaunchRequestV2,
        ready: ProtectedReadyV2,
        owned: ProtectedOwnedLaunchV2,
    },
    V3 {
        request: runne_api::ProtectedCredentialEnrollmentLaunchRequestV3,
        ready: runne_api::ProtectedCredentialEnrollmentReadyV3,
        owned: runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    },
    #[cfg(feature = "test-support")]
    #[allow(dead_code)]
    Test { owned: ProtectedOwnedLaunchV1 },
}

#[cfg(any(unix, windows))]
impl ProtectedProcessActivation {
    const fn compatibility_ready(&self) -> Option<&ProtectedReadyV1> {
        match self {
            Self::V1 { ready, .. } => Some(ready),
            Self::V2 { ready, .. } => Some(ready.compatibility_ready()),
            Self::V3 { .. } => None,
            #[cfg(feature = "test-support")]
            Self::Test { .. } => None,
        }
    }

    const fn compatibility_owned(&self) -> Option<&ProtectedOwnedLaunchV1> {
        match self {
            Self::V1 { owned, .. } => Some(owned),
            Self::V2 { owned, .. } => Some(owned.compatibility_owned_launch()),
            Self::V3 { .. } => None,
            #[cfg(feature = "test-support")]
            Self::Test { owned } => Some(owned),
        }
    }

    const fn provider_activation(&self) -> Option<&ProviderActivationBindingV1> {
        match self {
            Self::V1 { .. } => None,
            Self::V2 { request, .. } => Some(request.provider_binding()),
            Self::V3 { request, .. } => Some(request.provider_binding()),
            #[cfg(feature = "test-support")]
            Self::Test { .. } => None,
        }
    }
}

include!("process_v3.rs");

#[cfg(test)]
include!("v3_state_tests.rs");

/// Native development/ad-hoc launcher for a protected bundled daemon.
#[derive(Clone)]
pub struct DevelopmentBundledRuntimeLauncher {
    desktop_host_instance_id: [u8; 16],
}

impl fmt::Debug for DevelopmentBundledRuntimeLauncher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DevelopmentBundledRuntimeLauncher")
            .field("desktop_host", &"<native-instance>")
            .finish()
    }
}

impl Default for DevelopmentBundledRuntimeLauncher {
    fn default() -> Self {
        Self::new()
    }
}
