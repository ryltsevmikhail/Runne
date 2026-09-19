#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![allow(
    clippy::doc_markdown,
    clippy::match_same_arms,
    clippy::missing_const_for_fn,
    clippy::missing_errors_doc,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::redundant_pub_crate
)]

//! Bounded credential-free Anthropic Messages and Gemini text wire codecs.

mod profile;
mod render;
mod sse;
mod stream;

pub use profile::{
    AnthropicMessagesProfile, GeminiProfile, NativeAccounting, NativeWireProfile,
    NativeWireProfileError, WireLimits,
};
pub use render::{
    AnthropicMessagesRenderer, AnthropicRenderError, GeminiRenderError, GeminiRenderer,
};
pub use stream::{
    AnthropicStreamDecoder, AnthropicStreamError, GeminiStreamDecoder, GeminiStreamError,
};

/// Fixed Anthropic Messages request path owned by the adapter.
pub const ANTHROPIC_MESSAGES_PATH: &str = "/v1/messages";
/// Fixed Gemini streaming method suffix owned by the adapter.
pub const GEMINI_STREAM_METHOD: &str = ":streamGenerateContent?alt=sse";
