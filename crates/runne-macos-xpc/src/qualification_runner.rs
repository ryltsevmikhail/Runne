//! Closed native transport surface for one bootstrap qualification run.

use std::fmt;

use zeroize::Zeroizing;

use crate::peer_requirement::{MAX_REQUIREMENT_BYTES, valid_canonical_requirement};

pub const MAX_QUALIFICATION_RUNNER_FRAME_BYTES: usize = 64 * 1024;

/// The only installed Mach endpoints used by qualification bootstrap.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationRunnerEndpoint {
    DesktopBootstrap,
    RuntimeBootstrap,
    RootConsume,
}

impl QualificationRunnerEndpoint {
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) const fn mach_service_name(self) -> &'static str {
        match self {
            Self::DesktopBootstrap => "com.runne.qualification-runner.desktop-bootstrap.v1",
            Self::RuntimeBootstrap => "com.runne.qualification-runner.runtime-bootstrap.v1",
            Self::RootConsume => "com.runne.qualification-runner.root-consume.v1",
        }
    }

    pub(crate) const fn is_bootstrap(self) -> bool {
        !matches!(self, Self::RootConsume)
    }
}
/// Closed failures from qualification bootstrap transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationRunnerXpcError {
    Rejected,
    Unsupported,
    TimedOut,
    Interrupted,
    Invalidated,
    InvalidReply,
    OutcomeUnknown,
    Unavailable,
}

impl fmt::Display for QualificationRunnerXpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification runner native transport failed")
    }
}

impl std::error::Error for QualificationRunnerXpcError {}

/// Validated exact code-signing requirement, redacted from public diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct QualificationRunnerPeerRequirement(String);

impl QualificationRunnerPeerRequirement {
    /// Accepts only the canonical identifier, team, and `CDHash` requirement.
    ///
    /// # Errors
    ///
    /// Rejects malformed, multiline, or oversized requirements.
    pub fn new(value: impl Into<String>) -> Result<Self, QualificationRunnerXpcError> {
        let value = value.into();
        if value.len() > MAX_REQUIREMENT_BYTES || !valid_canonical_requirement(&value) {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        Ok(Self(value))
    }
    #[cfg(target_os = "macos")]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for QualificationRunnerPeerRequirement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QualificationRunnerPeerRequirement(<redacted>)")
    }
}

/// Expected login-session identity for one direction of a signed XPC connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationRunnerSessionBinding {
    expected_euid: u32,
    expected_audit_session: i32,
}

impl QualificationRunnerSessionBinding {
    /// Binds a peer to an expected EUID and nonzero audit session identifier.
    ///
    /// # Errors
    ///
    /// Rejects an invalid audit-session identifier.
    pub const fn new(
        expected_euid: u32,
        expected_audit_session: i32,
    ) -> Result<Self, QualificationRunnerXpcError> {
        if expected_audit_session < 0 {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        Ok(Self {
            expected_euid,
            expected_audit_session,
        })
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn expected_euid(self) -> u32 {
        self.expected_euid
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn expected_audit_session(self) -> i32 {
        self.expected_audit_session
    }
}

/// Exact endpoint, signing requirements, and direction-specific session bindings.
#[derive(Clone, Eq, PartialEq)]
pub struct QualificationRunnerEndpointConfiguration {
    endpoint: QualificationRunnerEndpoint,
    service_requirement: QualificationRunnerPeerRequirement,
    client_requirement: QualificationRunnerPeerRequirement,
    expected_client: QualificationRunnerSessionBinding,
    expected_service: QualificationRunnerSessionBinding,
}

impl QualificationRunnerEndpointConfiguration {
    /// Creates a fixed-endpoint configuration with both admission directions pinned.
    ///
    /// # Errors
    ///
    /// Rejects identical peer requirements, which cannot represent mutual admission.
    pub fn new(
        endpoint: QualificationRunnerEndpoint,
        service_requirement: QualificationRunnerPeerRequirement,
        client_requirement: QualificationRunnerPeerRequirement,
        expected_client: QualificationRunnerSessionBinding,
        expected_service: QualificationRunnerSessionBinding,
    ) -> Result<Self, QualificationRunnerXpcError> {
        let bootstrap_binding_is_valid = expected_client.expected_audit_session > 0
            && expected_service.expected_audit_session > 0;
        let root_binding_is_valid = expected_client.expected_audit_session > 0
            && expected_service.expected_euid == 0
            && expected_service.expected_audit_session == 0;
        if service_requirement == client_requirement
            || match endpoint {
                QualificationRunnerEndpoint::DesktopBootstrap
                | QualificationRunnerEndpoint::RuntimeBootstrap => !bootstrap_binding_is_valid,
                QualificationRunnerEndpoint::RootConsume => !root_binding_is_valid,
            }
        {
            return Err(QualificationRunnerXpcError::Rejected);
        }
        Ok(Self {
            endpoint,
            service_requirement,
            client_requirement,
            expected_client,
            expected_service,
        })
    }
    #[must_use]
    pub const fn endpoint(&self) -> QualificationRunnerEndpoint {
        self.endpoint
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn endpoint_name(&self) -> &'static str {
        self.endpoint.mach_service_name()
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn expected_client(&self) -> QualificationRunnerSessionBinding {
        self.expected_client
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn expected_service(&self) -> QualificationRunnerSessionBinding {
        self.expected_service
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn service_requirement(&self) -> &QualificationRunnerPeerRequirement {
        &self.service_requirement
    }
    #[cfg(target_os = "macos")]
    pub(crate) const fn client_requirement(&self) -> &QualificationRunnerPeerRequirement {
        &self.client_requirement
    }
}

impl fmt::Debug for QualificationRunnerEndpointConfiguration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualificationRunnerEndpointConfiguration")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

macro_rules! qualification_runner_frame {
    ($name:ident) => {
        /// Move-only bounded bootstrap control bytes; never an authority by themselves.
        pub struct $name(Zeroizing<Vec<u8>>);

        impl $name {
            /// Accepts one bounded, nonempty control frame.
            ///
            /// # Errors
            ///
            /// Rejects empty or oversized frames.
            pub fn from_zeroizing(
                bytes: Zeroizing<Vec<u8>>,
            ) -> Result<Self, QualificationRunnerXpcError> {
                if bytes.is_empty() || bytes.len() > MAX_QUALIFICATION_RUNNER_FRAME_BYTES {
                    return Err(QualificationRunnerXpcError::Rejected);
                }
                Ok(Self(bytes))
            }
            /// Transfers bounded control bytes; possession never grants authority.
            #[must_use]
            pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
                self.0
            }
        }
    };
}

qualification_runner_frame!(QualificationRunnerRequest);
qualification_runner_frame!(QualificationRunnerReply);

/// OS-observed peer identity provided to a per-connection session factory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QualificationRunnerPeer {
    euid: u32,
    audit_session: i32,
}

impl QualificationRunnerPeer {
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) const fn new(euid: u32, audit_session: i32) -> Self {
        Self {
            euid,
            audit_session,
        }
    }

    #[must_use]
    pub const fn euid(self) -> u32 {
        self.euid
    }

    #[must_use]
    pub const fn audit_session(self) -> i32 {
        self.audit_session
    }
}

/// Opaque transport-generated identity, retained by the downstream runner per connection.
pub struct QualificationRunnerSessionReceipt {
    _bytes: [u8; 32],
}

impl QualificationRunnerSessionReceipt {
    #[cfg(any(test, target_os = "macos"))]
    pub(crate) fn random() -> Result<Self, QualificationRunnerXpcError> {
        use rand::RngCore;
        let mut bytes = [0; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut bytes)
            .map_err(|_| QualificationRunnerXpcError::Unavailable)?;
        Ok(Self { _bytes: bytes })
    }
}

/// Creates a fresh runner-owned session for each accepted XPC connection.
pub trait QualificationRunnerSessionFactory: Send + Sync {
    /// Generates its own challenge and binds later consume to the opaque receipt.
    ///
    /// # Errors
    ///
    /// Returns a closed refusal when the runner cannot create this session.
    fn create_session(
        &self,
        context: crate::qualification_runner_session::QualificationRunnerSessionContext,
    ) -> Result<
        crate::qualification_runner_session::QualificationRunnerSessionLease,
        QualificationRunnerXpcError,
    >;
}

/// Per-connection bootstrap protocol state owned by the downstream runner.
pub trait QualificationRunnerSession: Send {
    /// Processes one bounded proof/control frame.
    ///
    /// # Errors
    ///
    /// Returns a closed failure and ends this session when the frame is invalid.
    fn exchange(
        &mut self,
        request: QualificationRunnerRequest,
    ) -> Result<QualificationRunnerReply, QualificationRunnerXpcError>;
}
