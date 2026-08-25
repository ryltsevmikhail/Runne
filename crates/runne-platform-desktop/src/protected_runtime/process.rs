
#[cfg(any(unix, windows))]
enum DesktopLaunchRequest {
    V1(ProtectedLaunchRequestV1),
    V2(ProtectedLaunchRequestV2),
}

#[cfg(any(unix, windows))]
impl DesktopLaunchRequest {
    const fn compatibility(&self) -> &ProtectedLaunchRequestV1 {
        match self {
            Self::V1(request) => request,
            Self::V2(request) => request.compatibility_request(),
        }
    }

    fn encode_frame(&self) -> Result<Vec<u8>, LaunchAuthorityError> {
        match self {
            Self::V1(request) => request.encode_frame(),
            Self::V2(request) => request.encode_frame(),
        }
        .map_err(|_| LaunchAuthorityError::InvalidContract)
    }

    fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        match self {
            Self::V1(request) => request.derive_keys_and_forget(),
            Self::V2(request) => request.derive_keys_and_forget(),
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
        }
    }
}

#[cfg(any(unix, windows))]
enum DesktopReady {
    V1(ProtectedReadyV1),
    V2(ProtectedReadyV2),
}

#[cfg(any(unix, windows))]
impl DesktopReady {
    const fn compatibility(&self) -> &ProtectedReadyV1 {
        match self {
            Self::V1(ready) => ready,
            Self::V2(ready) => ready.compatibility_ready(),
        }
    }

    /// Returns the authenticated provider readiness disposition for V2, or
    /// `None` for the V1 deterministic protocol which carries no disposition.
    const fn provider_readiness(&self) -> Option<ProviderActivationReadinessV1> {
        match self {
            Self::V1(_) => None,
            Self::V2(ready) => Some(ready.provider_readiness()),
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
            _ => Err(ProtectedBundledRuntimeError::InvalidState),
        }
    }
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
    #[cfg(feature = "test-support")]
    #[allow(dead_code)]
    Test { owned: ProtectedOwnedLaunchV1 },
}

#[cfg(any(unix, windows))]
impl ProtectedProcessActivation {
    #[allow(clippy::missing_const_for_fn)]
    fn compatibility_ready(&self) -> &ProtectedReadyV1 {
        match self {
            Self::V1 { ready, .. } => ready,
            Self::V2 { ready, .. } => ready.compatibility_ready(),
            #[cfg(feature = "test-support")]
            Self::Test { .. } => unreachable!("transport-only test process has no readiness"),
        }
    }

    const fn compatibility_owned(&self) -> &ProtectedOwnedLaunchV1 {
        match self {
            Self::V1 { owned, .. } => owned,
            Self::V2 { owned, .. } => owned.compatibility_owned_launch(),
            #[cfg(feature = "test-support")]
            Self::Test { owned } => owned,
        }
    }

    const fn provider_activation(&self) -> Option<&ProviderActivationBindingV1> {
        match self {
            Self::V1 { .. } => None,
            Self::V2 { request, .. } => Some(request.provider_binding()),
            #[cfg(feature = "test-support")]
            Self::Test { .. } => None,
        }
    }
}

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
