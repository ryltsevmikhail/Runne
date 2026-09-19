use runne_provider::{
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability,
};
use serde::Serialize;
use serde_json::Value;

use crate::{AnthropicMessagesProfile, GeminiProfile, WireLimits};

pub trait ProfileView {
    fn provider_id(&self) -> &str;
    fn model_id(&self) -> &str;
    fn model_revision(&self) -> &str;
    fn binding_extension(&self) -> Value;
    fn limits(&self) -> WireLimits;
}

impl ProfileView for AnthropicMessagesProfile {
    fn provider_id(&self) -> &str {
        self.provider_id()
    }
    fn model_id(&self) -> &str {
        self.model_id()
    }
    fn model_revision(&self) -> &str {
        self.model_revision()
    }
    fn binding_extension(&self) -> Value {
        self.binding_extension()
    }
    fn limits(&self) -> WireLimits {
        self.limits()
    }
}
impl ProfileView for GeminiProfile {
    fn provider_id(&self) -> &str {
        self.provider_id()
    }
    fn model_id(&self) -> &str {
        self.model_id()
    }
    fn model_revision(&self) -> &str {
        self.model_revision()
    }
    fn binding_extension(&self) -> Value {
        self.binding_extension()
    }
    fn limits(&self) -> WireLimits {
        self.limits()
    }
}

pub fn validate_call<P: ProfileView, E: Copy>(
    call: &ProviderCall,
    profile: &P,
    binding: E,
    capability: E,
    extension: E,
    bound: E,
) -> Result<(), E> {
    if call.model_ref().provider_id().as_str() != profile.provider_id()
        || call.model_ref().model_id() != profile.model_id()
        || call.model_ref().revision() != profile.model_revision()
    {
        return Err(binding);
    }
    if call.required_capabilities() != [ProviderCapability::Streaming] {
        return Err(capability);
    }
    if call.extension() != &profile.binding_extension() {
        return Err(extension);
    }
    if call.max_output_tokens() > profile.limits().max_output_tokens() {
        return Err(bound);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub enum PrepareFailure {
    Bound,
    Serialization,
}

pub fn prepare_json<T: Serialize>(
    call: &ProviderCall,
    request: &T,
    max: usize,
) -> Result<PreparedRequest, PrepareFailure> {
    let mut bytes = serde_json::to_vec(request).map_err(|_| PrepareFailure::Serialization)?;
    bytes.push(b'\n');
    if bytes.len() > max {
        return Err(PrepareFailure::Bound);
    }
    PreparedRequest::from_rendered_call_for_digest_version(
        call,
        ProviderCallDigestVersion::V2,
        bytes,
    )
    .map_err(|_| PrepareFailure::Serialization)
}
