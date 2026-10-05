#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Exact-profile `OpenAI` Responses text adapter contracts.

mod background_response;
pub mod canary;
mod credential;
mod profile;
mod render;
mod response_decode;
mod sse;
mod tool_profile;
mod tool_render;
mod transport;

pub use background_response::{
    OPENAI_MAX_BACKGROUND_STATUS_BYTES, OPENAI_MAX_BACKGROUND_TEXT_BYTES, OpenAiBackgroundResponse,
    OpenAiValidatedBackgroundTerminal,
};
pub use credential::{
    OpenAiBackgroundCredentialMaterializer, OpenAiCredentialError, OpenAiCredentialMaterializer,
};
pub use profile::{
    OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OPENAI_REQUEST_MODEL,
    OPENAI_RESPONSES_BACKGROUND_PROFILE_ID, OPENAI_RESPONSES_PROFILE_ID, OPENAI_SERVICE_TIER,
    OpenAiProfileError, OpenAiResponsesTextProfile,
};
pub use render::{OpenAiRenderError, OpenAiResponsesTextRenderer};
pub use response_decode::{decode_tool_transport_response, decode_transport_response};
pub use sse::{OpenAiSseDecoder, OpenAiStreamError};
pub use tool_profile::{OPENAI_RESPONSES_TOOL_PROFILE_ID, OpenAiResponsesToolProfile};
pub use tool_render::{OpenAiResponsesToolRenderer, OpenAiToolRenderError};
pub use transport::{
    OPENAI_MAX_DECODED_STREAM_BYTES, OPENAI_MAX_NORMALIZED_TEXT_BYTES, OPENAI_MAX_SSE_EVENTS,
    OPENAI_MAX_SSE_FRAME_BYTES, OPENAI_MAX_SSE_LINES, OPENAI_MAX_TRANSPORT_CHUNKS,
    OpenAiTransportError, OpenAiTransportPolicy, OpenAiTransportResponse,
};
