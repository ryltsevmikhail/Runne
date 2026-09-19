use runne_provider::{
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderCapability,
    ProviderInputRole, ProviderTextInput,
};
use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

use crate::RadiusProfile;

/// Radius request rendering failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RadiusRenderError {
    /// Provider/model/revision differs from the selected profile.
    #[error("Radius profile binding mismatch")]
    ProfileBindingMismatch,
    /// The call is not the bounded text-only streaming capability.
    #[error("Radius text-only capability required")]
    UnsupportedCapability,
    /// The dynamic catalog digest or model binding changed.
    #[error("Radius catalog binding mismatch")]
    CatalogBindingMismatch,
    /// Inputs are not an alternating user/assistant text conversation.
    #[error("Radius text context is invalid")]
    InvalidContext,
    /// A profile bound was exceeded.
    #[error("Radius request bound exceeded")]
    BoundExceeded,
    /// JSON serialization failed.
    #[error("Radius request serialization failed")]
    Serialization,
}

/// Credential-free Radius `pi-messages` renderer.
#[derive(Debug, Clone)]
pub struct RadiusRenderer {
    profile: RadiusProfile,
}

#[derive(Serialize)]
struct Request<'a> {
    model: &'a str,
    context: Context<'a>,
    options: Options,
}

#[derive(Serialize)]
struct Context<'a> {
    messages: Vec<Message<'a>>,
}

#[derive(Serialize)]
struct Message<'a> {
    role: &'a str,
    content: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Options {
    max_tokens: u32,
}

impl RadiusRenderer {
    /// Binds the renderer to one selected dynamic catalog model.
    pub const fn new(profile: RadiusProfile) -> Self {
        Self { profile }
    }
    /// Returns the exact profile extension required on a normalized call.
    pub fn binding_extension(&self) -> Value {
        json!({
            "radius_catalog_digest": hex::encode(self.profile.catalog_digest()),
            "radius_profile_digest": hex::encode(self.profile.profile_digest()),
            "radius_model_id": self.profile.model_id()
        })
    }
    /// Returns the profile used by this renderer.
    pub const fn profile(&self) -> &RadiusProfile {
        &self.profile
    }
    /// Renders `{model,context,options}` for the fixed `/messages` endpoint.
    pub fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, RadiusRenderError> {
        if call.model_ref().provider_id().as_str() != self.profile.provider_id()
            || call.model_ref().model_id() != self.profile.model_id()
            || call.model_ref().revision() != self.profile.revision()
        {
            return Err(RadiusRenderError::ProfileBindingMismatch);
        }
        if call.required_capabilities() != [ProviderCapability::Streaming] {
            return Err(RadiusRenderError::UnsupportedCapability);
        }
        if call.extension() != &self.binding_extension() {
            return Err(RadiusRenderError::CatalogBindingMismatch);
        }
        if call.max_output_tokens() > self.profile.max_tokens() {
            return Err(RadiusRenderError::BoundExceeded);
        }
        let inputs = call.text_inputs();
        if inputs.is_empty() || inputs.len() > 256 {
            return Err(RadiusRenderError::InvalidContext);
        }
        let mut expected = ProviderInputRole::User;
        let mut messages = Vec::with_capacity(inputs.len());
        let mut input_bytes = 0_usize;
        for input in inputs {
            input_bytes = input_bytes
                .checked_add(input.text().len())
                .ok_or(RadiusRenderError::BoundExceeded)?;
            if input.role() != expected
                || input.text().len() > 262_144
                || input_bytes > self.profile.max_input_bytes()
            {
                return Err(RadiusRenderError::InvalidContext);
            }
            messages.push(Message {
                role: if input.role() == ProviderInputRole::User {
                    "user"
                } else {
                    "assistant"
                },
                content: input.text(),
            });
            expected = if expected == ProviderInputRole::User {
                ProviderInputRole::Assistant
            } else {
                ProviderInputRole::User
            };
        }
        if inputs.last().map(ProviderTextInput::role) != Some(ProviderInputRole::User) {
            return Err(RadiusRenderError::InvalidContext);
        }
        let request = Request {
            model: self.profile.model_id(),
            context: Context { messages },
            options: Options {
                max_tokens: call.max_output_tokens(),
            },
        };
        let mut bytes =
            serde_json::to_vec(&request).map_err(|_| RadiusRenderError::Serialization)?;
        bytes.push(b'\n');
        if bytes.len() > 524_288 {
            return Err(RadiusRenderError::BoundExceeded);
        }
        PreparedRequest::from_rendered_call_for_digest_version(
            call,
            ProviderCallDigestVersion::V2,
            bytes,
        )
        .map_err(|_| RadiusRenderError::Serialization)
    }
}
