#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Shared bounded `OpenAI` Chat Completions text adapter.

mod configured;
mod configured_limits;
mod profile;
mod profile_digest;
mod profile_limits;
mod quota;
mod registry;
mod render;
mod stream;
mod stream_rejection;
mod stream_types;

#[cfg(test)]
mod configured_tests;

pub use configured::{
    ConfiguredChatProfile, ConfiguredChatProfileError, ConfiguredChatProvider, bedrock,
    bedrock_with_limits, cloudflare_gateway, cloudflare_gateway_with_limits, cloudflare_workers,
    cloudflare_workers_with_limits, nvidia, nvidia_with_limits,
};
pub use configured_limits::ConfiguredChatModelLimits;
pub use profile::{
    ChatCompletionsAccounting, ChatCompletionsBillingMode, ChatCompletionsProfile,
    ChatCompletionsProfileError, ChatCompletionsThinkingMode,
};
pub use profile_limits::ChatCompletionsModelLimits;
pub use quota::{
    QuotaAdmissionError, QuotaSourceV1, QuotaUnitV1, SubscriptionQuotaReader,
    SubscriptionQuotaSnapshotV1,
};
pub use registry::{GenericChatProfile, generic_profile, generic_profiles};
pub use render::{ChatCompletionsRenderError, ChatCompletionsRenderer};
pub use stream::{ChatCompletionsStreamDecoder, ChatCompletionsStreamError};
pub use stream_rejection::normalize_json_rejection;
