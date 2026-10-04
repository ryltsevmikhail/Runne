use core::fmt;

use crate::{
    ProviderRecoveryBinding, ProviderRecoveryError, ProviderRecoveryOperation,
    ProviderRemoteOperationProof, ProviderRemoteResponseStatus, RemoteResponseId,
};

impl fmt::Debug for crate::RemoteResponseId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemoteResponseId([redacted])")
    }
}

impl fmt::Debug for ProviderRemoteResponseStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (name, usage) = match self {
            Self::Pending => ("pending", None),
            Self::Completed { usage } => ("completed", *usage),
            Self::Failed { usage, .. } => ("failed", *usage),
            Self::Incomplete { usage, .. } => ("incomplete", *usage),
            Self::Cancelled { usage } => ("cancelled", *usage),
            Self::Unknown => ("unknown", None),
        };
        formatter
            .debug_struct("ProviderRemoteResponseStatus")
            .field("outcome", &name)
            .field("usage", &usage)
            .finish()
    }
}

/// Validated terminal data returned by an exact remote status observation.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteTerminalArtifact {
    response_id: RemoteResponseId,
    status: ProviderRemoteResponseStatus,
    output_text: Option<String>,
    publication: ProviderRemotePublicationDisposition,
}

/// Local scanner decision for publication of remote text, independent of remote outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderRemotePublicationDisposition {
    /// The complete snapshot passed the current prohibited-content scanner.
    Allowed,
    /// Remote terminal status is factual, but text cannot be published locally.
    Rejected(crate::ScannerTerminalDisposition),
}

impl ProviderRemoteTerminalArtifact {
    /// Constructs terminal evidence after provider-specific profile and ID validation.
    pub fn new(
        response_id: RemoteResponseId,
        status: ProviderRemoteResponseStatus,
        output_text: Option<String>,
    ) -> Result<Self, ProviderRecoveryError> {
        Self::new_with_publication_disposition(
            response_id,
            status,
            output_text,
            ProviderRemotePublicationDisposition::Allowed,
        )
    }

    /// Constructs factual terminal evidence with a distinct local publication decision.
    pub fn new_with_publication_disposition(
        response_id: RemoteResponseId,
        status: ProviderRemoteResponseStatus,
        output_text: Option<String>,
        publication: ProviderRemotePublicationDisposition,
    ) -> Result<Self, ProviderRecoveryError> {
        if matches!(
            &status,
            ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown
        ) || output_text.as_ref().is_some_and(|text| text.len() > 65_536)
            || (matches!(&status, ProviderRemoteResponseStatus::Completed { .. })
                && output_text.is_none()
                && publication == ProviderRemotePublicationDisposition::Allowed)
            || (matches!(
                publication,
                ProviderRemotePublicationDisposition::Rejected(_)
            ) && output_text.is_some())
            || matches!(
                publication,
                ProviderRemotePublicationDisposition::Rejected(
                    crate::ScannerTerminalDisposition::Completed
                )
            )
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            response_id,
            status,
            output_text,
            publication,
        })
    }

    /// Returns the exact remote response whose terminal content was validated.
    pub fn response_id(&self) -> &RemoteResponseId {
        &self.response_id
    }

    /// Returns the exact remote terminal outcome and any provider-reported usage.
    pub const fn status(&self) -> &ProviderRemoteResponseStatus {
        &self.status
    }

    /// Returns validated text without placing it in diagnostics.
    pub fn output_text(&self) -> Option<&str> {
        self.output_text.as_deref()
    }

    /// Returns whether local publication may use this remote snapshot's text.
    pub const fn publication_disposition(&self) -> ProviderRemotePublicationDisposition {
        self.publication
    }
}

impl fmt::Debug for ProviderRemoteTerminalArtifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRemoteTerminalArtifact")
            .field("outcome", &status_name(&self.status))
            .field(
                "output_text_bytes",
                &self.output_text.as_ref().map(String::len),
            )
            .finish()
    }
}

/// Status observation with an optional fully validated terminal artifact.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderRemoteCheck {
    binding: ProviderRecoveryBinding,
    response_id: RemoteResponseId,
    status: ProviderRemoteResponseStatus,
    terminal: Option<ProviderRemoteTerminalArtifact>,
    operation_proof: Option<ProviderRemoteOperationProof>,
}

impl ProviderRemoteCheck {
    /// Constructs a status observation, requiring artifact and status agreement.
    pub fn new(
        binding: ProviderRecoveryBinding,
        response_id: RemoteResponseId,
        status: ProviderRemoteResponseStatus,
        terminal: Option<ProviderRemoteTerminalArtifact>,
    ) -> Result<Self, ProviderRecoveryError> {
        let is_terminal = !matches!(
            &status,
            ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown
        );
        if is_terminal != terminal.is_some()
            || terminal.as_ref().is_some_and(|artifact| {
                artifact.status != status || artifact.response_id != response_id
            })
        {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        Ok(Self {
            binding,
            response_id,
            status,
            terminal,
            operation_proof: None,
        })
    }

    /// Constructs a check tied to the fresh operation that produced its response.
    pub fn new_authorized(
        binding: ProviderRecoveryBinding,
        response_id: RemoteResponseId,
        status: ProviderRemoteResponseStatus,
        terminal: Option<ProviderRemoteTerminalArtifact>,
        operation: ProviderRecoveryOperation,
        operation_proof: ProviderRemoteOperationProof,
    ) -> Result<Self, ProviderRecoveryError> {
        if !operation_proof.matches(binding, operation, &response_id) {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let mut check = Self::new(binding, response_id, status, terminal)?;
        check.operation_proof = Some(operation_proof);
        Ok(check)
    }

    /// Returns the historical TaskRun, attempt, and profile binding.
    pub const fn binding(&self) -> ProviderRecoveryBinding {
        self.binding
    }

    /// Returns the exact response identity checked by the remote operation.
    pub fn response_id(&self) -> &RemoteResponseId {
        &self.response_id
    }

    /// Returns the observed remote status.
    pub const fn status(&self) -> &ProviderRemoteResponseStatus {
        &self.status
    }

    /// Returns complete validated terminal data when the response is terminal.
    pub const fn terminal(&self) -> Option<&ProviderRemoteTerminalArtifact> {
        self.terminal.as_ref()
    }

    /// Returns the one-use proof for persisting this operation's observation.
    pub const fn operation_proof(&self) -> Option<&ProviderRemoteOperationProof> {
        self.operation_proof.as_ref()
    }
}

impl fmt::Debug for ProviderRemoteCheck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderRemoteCheck")
            .field("outcome", &status_name(&self.status))
            .field("response_id", &self.response_id)
            .field("terminal", &self.terminal.is_some())
            .field("has_operation_proof", &self.operation_proof.is_some())
            .finish()
    }
}

fn status_name(status: &ProviderRemoteResponseStatus) -> &'static str {
    match status {
        ProviderRemoteResponseStatus::Pending => "pending",
        ProviderRemoteResponseStatus::Completed { .. } => "completed",
        ProviderRemoteResponseStatus::Failed { .. } => "failed",
        ProviderRemoteResponseStatus::Incomplete { .. } => "incomplete",
        ProviderRemoteResponseStatus::Cancelled { .. } => "cancelled",
        ProviderRemoteResponseStatus::Unknown => "unknown",
    }
}
