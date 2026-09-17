use std::time::Instant;

use crate::qualification_runner::{
    QualificationRunnerEndpoint, QualificationRunnerEndpointConfiguration,
    QualificationRunnerReply, QualificationRunnerRequest, QualificationRunnerXpcError,
};

/// Client for one fixed qualification bootstrap endpoint.
pub struct QualificationRunnerXpcClient {
    #[cfg(target_os = "macos")]
    native: crate::client::native::NativeClient,
}

impl QualificationRunnerXpcClient {
    /// Connects only to the desktop or runtime bootstrap endpoint in `configuration`.
    ///
    /// # Errors
    ///
    /// Rejects root-consume and fails closed outside macOS.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::missing_const_for_fn,
            reason = "The non-macOS stub keeps the same public constructor shape as macOS."
        )
    )]
    pub fn connect_bootstrap(
        configuration: &QualificationRunnerEndpointConfiguration,
    ) -> Result<Self, QualificationRunnerXpcError> {
        if !configuration.endpoint().is_bootstrap() {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        Self::connect(configuration)
    }

    /// Connects only to the fixed privileged root-consume endpoint.
    ///
    /// # Errors
    ///
    /// Rejects every non-root endpoint and fails closed outside macOS.
    pub fn connect_root_consume(
        configuration: &QualificationRunnerEndpointConfiguration,
    ) -> Result<Self, QualificationRunnerXpcError> {
        if configuration.endpoint() != QualificationRunnerEndpoint::RootConsume {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        Self::connect(configuration)
    }

    #[cfg(target_os = "macos")]
    fn connect(
        configuration: &QualificationRunnerEndpointConfiguration,
    ) -> Result<Self, QualificationRunnerXpcError> {
        use crate::client::native::NativePeerBinding;

        let binding = configuration.expected_service();
        let native = crate::client::native::NativeClient::connect_qualification(
            configuration.endpoint(),
            configuration.service_requirement().as_str(),
            NativePeerBinding {
                expected_euid: binding.expected_euid(),
                expected_audit_session: binding.expected_audit_session(),
            },
        )
        .map_err(map_error)?;
        Ok(Self { native })
    }

    #[cfg(not(target_os = "macos"))]
    const fn connect(
        _: &QualificationRunnerEndpointConfiguration,
    ) -> Result<Self, QualificationRunnerXpcError> {
        Err(QualificationRunnerXpcError::Unsupported)
    }

    /// Exchanges one bounded control frame before the supplied monotonic deadline.
    ///
    /// Any error invalidates this connection. A caller must reconnect, producing a
    /// fresh session and challenge rather than resuming this one.
    ///
    /// # Errors
    ///
    /// Returns a terminal closed disposition for timeout, peer mismatch, or reply failure.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::unused_async,
            reason = "The non-macOS stub keeps the async exchange API used by cross-platform callers."
        )
    )]
    pub async fn exchange(
        &self,
        request: QualificationRunnerRequest,
        deadline: Instant,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError> {
        #[cfg(target_os = "macos")]
        {
            let mut terminal_guard = QualificationRunnerDispatchGuard::new(&self.native);
            self.native
                .begin_qualification_exchange(deadline)
                .map_err(map_error)?;
            let context =
                runne_platform_ports::credential_service::CredentialServiceCallContext::new(
                    deadline,
                    runne_platform_ports::credential_service::CredentialServiceCancellation::new(),
                );
            let bytes = self
                .native
                .exchange(request.into_zeroizing(), context)
                .await
                .map_err(map_error)?;
            self.native
                .revalidate_qualification_peer(deadline)
                .map_err(map_error)?;
            let reply = QualificationRunnerReply::from_zeroizing(bytes)?;
            terminal_guard.disarm();
            Ok(reply)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (self, request, deadline);
            Err(QualificationRunnerXpcError::Unsupported)
        }
    }

    /// Revalidates the peer observed by a successful prior native reply.
    ///
    /// # Errors
    ///
    /// Rejects a client without an observed peer-verified reply, an inactive
    /// connection, a changed peer identity, or an expired deadline. Any error
    /// leaves this client terminal.
    #[cfg_attr(
        not(target_os = "macos"),
        expect(
            clippy::missing_const_for_fn,
            reason = "The non-macOS stub keeps the same public method shape as macOS."
        )
    )]
    pub fn revalidate_peer(&self, deadline: Instant) -> Result<(), QualificationRunnerXpcError> {
        #[cfg(target_os = "macos")]
        {
            self.native
                .revalidate_qualification_peer(deadline)
                .map_err(map_error)
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (self, deadline);
            Err(QualificationRunnerXpcError::Unsupported)
        }
    }
}

#[cfg(target_os = "macos")]
struct QualificationRunnerDispatchGuard<'a> {
    native: &'a crate::client::native::NativeClient,
    armed: bool,
}

#[cfg(target_os = "macos")]
impl<'a> QualificationRunnerDispatchGuard<'a> {
    const fn new(native: &'a crate::client::native::NativeClient) -> Self {
        Self {
            native,
            armed: true,
        }
    }

    const fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(target_os = "macos")]
impl Drop for QualificationRunnerDispatchGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.native.invalidate();
        }
    }
}

#[cfg(target_os = "macos")]
const fn map_error(error: crate::CredentialServiceXpcError) -> QualificationRunnerXpcError {
    use crate::CredentialServiceXpcError as Source;
    match error {
        Source::Rejected | Source::VersionSkew | Source::ApprovalRequired | Source::NotFound => {
            QualificationRunnerXpcError::Rejected
        }
        Source::Unsupported => QualificationRunnerXpcError::Unsupported,
        Source::TimedOut => QualificationRunnerXpcError::TimedOut,
        Source::Interrupted => QualificationRunnerXpcError::Interrupted,
        Source::Invalidated => QualificationRunnerXpcError::Invalidated,
        Source::InvalidReply => QualificationRunnerXpcError::InvalidReply,
        Source::OutcomeUnknown | Source::Cancelled => QualificationRunnerXpcError::OutcomeUnknown,
        Source::Unavailable => QualificationRunnerXpcError::Unavailable,
    }
}
