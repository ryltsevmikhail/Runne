use std::fmt;

/// Process role that may terminate at an exact qualification point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationProcessRole {
    Desktop,
    Writer,
    Runtime,
    Service,
}

/// Closed set of qualification-only process-death points.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationFaultSelector {
    BeforeServiceConsume,
    AfterServiceConsume,
    BeforeNativeEffect,
    AfterNativeEffect,
    BeforeReadback,
    AfterReadback,
    BeforeReply,
    AfterReply,
    BeforeLifecycleCas,
    AfterLifecycleCas,
    DesktopProcess,
    WriterProcess,
    RuntimeProcess,
    ServiceLaunchdRestart,
    RegistrationAckLoss,
}

impl QualificationFaultSelector {
    /// Returns the exact canonical selector written into a fault ticket.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BeforeServiceConsume => "kill_before_service_consume",
            Self::AfterServiceConsume => "kill_after_service_consume",
            Self::BeforeNativeEffect => "kill_before_native_effect",
            Self::AfterNativeEffect => "kill_after_native_effect",
            Self::BeforeReadback => "kill_before_readback",
            Self::AfterReadback => "kill_after_readback",
            Self::BeforeReply => "kill_before_reply",
            Self::AfterReply => "kill_after_reply",
            Self::BeforeLifecycleCas => "kill_before_lifecycle_cas",
            Self::AfterLifecycleCas => "kill_after_lifecycle_cas",
            Self::DesktopProcess => "kill_desktop_process",
            Self::WriterProcess => "kill_writer_process",
            Self::RuntimeProcess => "kill_runtime_process",
            Self::ServiceLaunchdRestart => "kill_service_launchd_restart",
            Self::RegistrationAckLoss => "kill_registration_ack_loss",
        }
    }

    /// Returns the only process role allowed to consume this selector.
    #[must_use]
    pub const fn process_role(self) -> QualificationProcessRole {
        match self {
            Self::DesktopProcess => QualificationProcessRole::Desktop,
            Self::WriterProcess => QualificationProcessRole::Writer,
            Self::BeforeLifecycleCas | Self::AfterLifecycleCas | Self::RuntimeProcess => {
                QualificationProcessRole::Runtime
            }
            Self::BeforeServiceConsume
            | Self::AfterServiceConsume
            | Self::BeforeNativeEffect
            | Self::AfterNativeEffect
            | Self::BeforeReadback
            | Self::AfterReadback
            | Self::BeforeReply
            | Self::AfterReply
            | Self::ServiceLaunchdRestart
            | Self::RegistrationAckLoss => QualificationProcessRole::Service,
        }
    }

    pub(super) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "kill_before_service_consume" => Self::BeforeServiceConsume,
            "kill_after_service_consume" => Self::AfterServiceConsume,
            "kill_before_native_effect" => Self::BeforeNativeEffect,
            "kill_after_native_effect" => Self::AfterNativeEffect,
            "kill_before_readback" => Self::BeforeReadback,
            "kill_after_readback" => Self::AfterReadback,
            "kill_before_reply" => Self::BeforeReply,
            "kill_after_reply" => Self::AfterReply,
            "kill_before_lifecycle_cas" => Self::BeforeLifecycleCas,
            "kill_after_lifecycle_cas" => Self::AfterLifecycleCas,
            "kill_desktop_process" => Self::DesktopProcess,
            "kill_writer_process" => Self::WriterProcess,
            "kill_runtime_process" => Self::RuntimeProcess,
            "kill_service_launchd_restart" => Self::ServiceLaunchdRestart,
            "kill_registration_ack_loss" => Self::RegistrationAckLoss,
            _ => return None,
        })
    }
}

impl QualificationProcessRole {
    pub(super) fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "desktop" => Self::Desktop,
            "writer" => Self::Writer,
            "runtime" => Self::Runtime,
            "service" => Self::Service,
            _ => return None,
        })
    }
}

/// Exact non-secret execution context against which a ticket is bound.
pub struct QualificationFaultContext {
    pub(super) selector: QualificationFaultSelector,
    pub(super) process_role: QualificationProcessRole,
    pub(super) candidate_sha256: [u8; 32],
    pub(super) release_tuple_v3_sha256: [u8; 32],
    pub(super) source_revision: [u8; 20],
    pub(super) workflow_run_id: String,
    pub(super) namespace_sha256: [u8; 32],
}

impl QualificationFaultContext {
    /// Constructs one exact runner-bound verification context.
    ///
    /// # Errors
    ///
    /// Returns [`QualificationFaultError::InvalidContext`] for a noncanonical
    /// workflow run identifier.
    pub fn new(
        selector: QualificationFaultSelector,
        process_role: QualificationProcessRole,
        candidate_sha256: [u8; 32],
        release_tuple_v3_sha256: [u8; 32],
        source_revision: [u8; 20],
        workflow_run_id: &str,
        namespace_sha256: [u8; 32],
    ) -> Result<Self, QualificationFaultError> {
        if !valid_run_id(workflow_run_id) {
            return Err(QualificationFaultError::InvalidContext);
        }
        Ok(Self {
            selector,
            process_role,
            candidate_sha256,
            release_tuple_v3_sha256,
            source_revision,
            workflow_run_id: workflow_run_id.to_owned(),
            namespace_sha256,
        })
    }
}

pub fn valid_run_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

/// Opaque canonical ticket retained between native admission and exact use.
pub struct PendingQualificationFault {
    bytes: Vec<u8>,
}

impl PendingQualificationFault {
    /// Retains one already-admitted canonical ticket frame without verifying
    /// authority or context.
    ///
    /// # Errors
    ///
    /// Rejects empty, oversized, noncanonical, trailing, or semantically invalid input.
    pub fn from_admitted_frame(bytes: Vec<u8>) -> Result<Self, QualificationFaultError> {
        let ticket = crate::wire::decode(&bytes)?;
        crate::verification::validate_admitted_shape(
            &ticket,
            QualificationFaultError::InvalidTicket,
        )?;
        Ok(Self { bytes })
    }

    /// Consumes this pending frame through the exact verifier and context.
    ///
    /// # Errors
    ///
    /// Returns the verifier's closed rejection without exposing retained bytes.
    pub fn verify_and_consume(
        self,
        verifier: &mut crate::QualificationFaultVerifier,
        context: &QualificationFaultContext,
        now_unix_seconds: u64,
    ) -> Result<VerifiedQualificationFault, QualificationFaultError> {
        verifier.verify_and_consume(&self.bytes, context, now_unix_seconds)
    }
}

/// Opaque single-use authority produced only after complete ticket verification.
pub struct VerifiedQualificationFault {
    pub(super) selector: QualificationFaultSelector,
    pub(super) process_role: QualificationProcessRole,
    pub(super) ticket_id: [u8; 32],
    pub(super) nonce: [u8; 32],
    pub(super) expires_at: u64,
}

impl VerifiedQualificationFault {
    #[must_use]
    pub const fn selector(&self) -> QualificationFaultSelector {
        self.selector
    }

    #[must_use]
    pub const fn process_role(&self) -> QualificationProcessRole {
        self.process_role
    }

    #[must_use]
    pub const fn ticket_id(&self) -> [u8; 32] {
        self.ticket_id
    }

    #[must_use]
    pub const fn nonce(&self) -> [u8; 32] {
        self.nonce
    }

    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

impl fmt::Debug for VerifiedQualificationFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedQualificationFault(<verified>)")
    }
}

/// Closed failure classes for fault-ticket verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QualificationFaultError {
    PolicyUnavailable,
    InvalidContext,
    InvalidTicket,
    InvalidTime,
    InvalidSignature,
    ContextMismatch,
    Replay,
}

impl fmt::Display for QualificationFaultError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("qualification fault ticket rejected")
    }
}

impl std::error::Error for QualificationFaultError {}
