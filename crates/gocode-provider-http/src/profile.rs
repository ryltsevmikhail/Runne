use gocode_provider::{ProviderCall, ProviderCapability, ProviderId};
use thiserror::Error;

/// Exact immutable HTTP adapter activation profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderAdapterProfile {
    /// Profile identity bound into each request.
    pub profile_digest: [u8; 32],
    /// Exact provider identity.
    pub provider_id: ProviderId,
    /// Exact model identity.
    pub model_id: String,
    /// Exact model revision.
    pub model_revision: String,
    /// Exact pricing snapshot digest.
    pub pricing_digest: [u8; 32],
    /// HTTPS origin without path.
    pub origin: String,
    /// Exact request path.
    pub path: String,
    /// Maximum response body bytes.
    pub max_body_bytes: usize,
    /// Maximum normalized frame bytes.
    pub max_frame_bytes: usize,
    /// Exact enabled capabilities.
    pub capabilities: Vec<ProviderCapability>,
}

/// Profile or request binding failure.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ProfileError {
    /// Profile contains an unsafe or ambiguous transport setting.
    #[error("invalid provider adapter profile")]
    InvalidProfile,
    /// Provider/model/revision/profile/pricing binding differs.
    #[error("provider call does not match the exact adapter profile")]
    BindingMismatch,
    /// Required capability is unavailable.
    #[error("provider capability is unavailable")]
    CapabilityUnavailable,
}

impl ProviderAdapterProfile {
    /// Validates exact origin, path and bounds.
    pub fn validate(&self) -> Result<(), ProfileError> {
        if !self.origin.starts_with("https://")
            || self.origin["https://".len()..].contains('/')
            || !self.path.starts_with('/')
            || self.path.starts_with("//")
            || self.max_body_bytes == 0
            || self.max_frame_bytes == 0
            || self.max_frame_bytes > self.max_body_bytes
            || self.model_id.is_empty()
            || self.model_revision.is_empty()
        {
            return Err(ProfileError::InvalidProfile);
        }
        Ok(())
    }

    pub(crate) fn validate_call(&self, call: &ProviderCall) -> Result<(), ProfileError> {
        let extension = call.extension();
        let expected_profile = hex_digest(self.profile_digest);
        let expected_pricing = hex_digest(self.pricing_digest);
        if call.model_ref().provider_id() != &self.provider_id
            || call.model_ref().model_id() != self.model_id
            || call.model_ref().revision() != self.model_revision
            || extension
                .get("profile_digest")
                .and_then(|value| value.as_str())
                != Some(expected_profile.as_str())
            || extension
                .get("pricing_digest")
                .and_then(|value| value.as_str())
                != Some(expected_pricing.as_str())
        {
            return Err(ProfileError::BindingMismatch);
        }
        if call
            .required_capabilities()
            .iter()
            .any(|capability| !self.capabilities.contains(capability))
        {
            return Err(ProfileError::CapabilityUnavailable);
        }
        Ok(())
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
