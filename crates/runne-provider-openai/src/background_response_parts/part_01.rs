use runne_provider::{
    ProviderRecoveryBinding, ProviderRecoveryError, ProviderRemoteCheck,
    ProviderRemoteResponseStatus, ProviderRemoteTerminalArtifact, ProviderUsage, RemoteResponseId,
};
use serde_json::{Map, Value};
use std::fmt;

use crate::{OpenAiResponsesTextProfile, OpenAiStreamError};

/// Maximum JSON body accepted for a background Responses status envelope.
pub const OPENAI_MAX_BACKGROUND_STATUS_BYTES: usize = 4_194_304;
/// Full factual status envelope/output text accepted before local publication scanning.
pub const OPENAI_MAX_BACKGROUND_TEXT_BYTES: usize = 4_194_304;

/// Initial response ID and reported state; it is not settlement proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenAiBackgroundResponse {
    response_id: RemoteResponseId,
    status: ProviderRemoteResponseStatus,
}

impl OpenAiBackgroundResponse {
    /// Parses a bounded response envelope without using diagnostic request IDs.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid response ID, status, usage record, or byte bound.
    pub fn from_json(bytes: &[u8]) -> Result<Self, ProviderRecoveryError> {
        let value = parse_value(bytes).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        let object = value
            .as_object()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        let response_id =
            openai_response_id(object).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        let status = remote_status(object).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        Ok(Self {
            response_id,
            status,
        })
    }

    /// Parses a status envelope bound to the exact background profile and GET target.
    ///
    /// # Errors
    ///
    /// Returns an error when the body, response identity, or profile guards are invalid.
    pub fn from_json_for_profile(
        bytes: &[u8],
        profile: &OpenAiResponsesTextProfile,
        expected_response_id: &RemoteResponseId,
    ) -> Result<Self, ProviderRecoveryError> {
        if !profile.is_background() {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let value = parse_value(bytes).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        let object = value
            .as_object()
            .ok_or(ProviderRecoveryError::InvalidIdentity)?;
        validate_profile_guards(object, profile)
            .map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        let response_id =
            openai_response_id(object).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        if response_id != *expected_response_id {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        let status = remote_status(object).map_err(|_| ProviderRecoveryError::InvalidIdentity)?;
        Ok(Self {
            response_id,
            status,
        })
    }

    /// Returns the provider response ID for persistence before event publication.
    #[must_use]
    pub const fn response_id(&self) -> &RemoteResponseId {
        &self.response_id
    }

    /// Returns the reported state, which must not be treated as settlement proof.
    #[must_use]
    pub const fn status(&self) -> &ProviderRemoteResponseStatus {
        &self.status
    }

    /// Converts a pending or unknown envelope without asserting settlement.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope is terminal or its local binding is invalid.
    pub fn into_nonterminal_check(
        self,
        binding: ProviderRecoveryBinding,
    ) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
        if !matches!(
            &self.status,
            ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown
        ) {
            return Err(ProviderRecoveryError::InvalidIdentity);
        }
        ProviderRemoteCheck::new(binding, self.response_id, self.status, None)
    }
}

/// A structurally validated terminal background response.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenAiValidatedBackgroundTerminal {
    response_id: RemoteResponseId,
    status: ProviderRemoteResponseStatus,
    output_text: Option<String>,
}

impl fmt::Debug for OpenAiValidatedBackgroundTerminal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenAiValidatedBackgroundTerminal")
            .field("response_id", &self.response_id)
            .field("status", &self.status)
            .field(
                "output_text_bytes",
                &self.output_text.as_ref().map(String::len),
            )
            .finish()
    }
}

impl OpenAiValidatedBackgroundTerminal {
    /// Validates exact profile, response identity, terminal fields, output, and usage.
    ///
    /// # Errors
    ///
    /// Returns an error when the envelope is not exact terminal evidence for this profile and ID.
    pub fn from_json(
        bytes: &[u8],
        profile: &OpenAiResponsesTextProfile,
        expected_response_id: &RemoteResponseId,
    ) -> Result<Self, OpenAiStreamError> {
        if !profile.is_background() {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        let value = parse_value(bytes)?;
        let object = value.as_object().ok_or(OpenAiStreamError::MalformedEvent)?;
        let response_id = openai_response_id(object)?;
        if response_id != *expected_response_id {
            return Err(OpenAiStreamError::CorrelationMismatch);
        }
        validate_profile_guards(object, profile)?;
        let status_text = string_field(object, "status")?;
        let status = remote_status(object).map_err(|_| OpenAiStreamError::InvalidUsage)?;
        if matches!(
            &status,
            ProviderRemoteResponseStatus::Pending | ProviderRemoteResponseStatus::Unknown
        ) {
            return Err(OpenAiStreamError::TerminalMissing);
        }
        validate_terminal_fields(object, status_text)?;
        let output_text = validate_terminal_output(object, status_text)?;
        if matches!(&status, ProviderRemoteResponseStatus::Completed { .. })
            && output_text.is_none()
        {
            return Err(OpenAiStreamError::MalformedEvent);
        }
        Ok(Self {
            response_id,
            status,
            output_text,
        })
    }

    /// Returns the response identity matching the exact GET target.
    #[must_use]
    pub const fn response_id(&self) -> &RemoteResponseId {
        &self.response_id
    }
    /// Returns the validated explicit provider outcome and actual usage if present.
    #[must_use]
    pub const fn status(&self) -> &ProviderRemoteResponseStatus {
        &self.status
    }
    /// Returns validated assistant text, redacted from Debug output.
    #[must_use]
    pub fn output_text(&self) -> Option<&str> {
        self.output_text.as_deref()
    }

    /// Converts this validated terminal into a bounded provider-neutral artifact.
    ///
    /// # Errors
    ///
    /// Returns an error when the terminal identity or bounded artifact is invalid.
    pub fn into_remote_check(
        self,
        binding: ProviderRecoveryBinding,
    ) -> Result<ProviderRemoteCheck, ProviderRecoveryError> {
        let oversized = self
            .output_text
            .as_ref()
            .is_some_and(|text| text.len() > 65_536);
        let terminal = if oversized {
            ProviderRemoteTerminalArtifact::new_with_publication_disposition(
                self.response_id.clone(),
                self.status.clone(),
                None,
                runne_provider::ProviderRemotePublicationDisposition::Rejected(
                    runne_provider::ScannerTerminalDisposition::OutputLimitExceeded,
                ),
            )?
        } else {
            ProviderRemoteTerminalArtifact::new(
                self.response_id.clone(),
                self.status.clone(),
                self.output_text,
            )?
        };
        ProviderRemoteCheck::new(binding, self.response_id, self.status, Some(terminal))
    }
}
