#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Exact-profile `OpenAI` Responses text adapter contracts.

mod adapter;
mod credential;
mod profile;
mod render;
mod sse;
mod transport;

pub use adapter::{OpenAiAdapterError, OpenAiProviderAdapter};
pub use credential::{OpenAiCredentialError, OpenAiCredentialMaterializer};
pub use profile::{
    OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OPENAI_REQUEST_MODEL, OPENAI_RESPONSES_PROFILE_ID,
    OPENAI_SERVICE_TIER, OpenAiProfileError, OpenAiResponsesTextProfile,
};
pub use render::{OpenAiRenderError, OpenAiResponsesTextRenderer};
pub use sse::{OpenAiSseDecoder, OpenAiStreamError};
pub use transport::{
    OPENAI_MAX_DECODED_STREAM_BYTES, OPENAI_MAX_NORMALIZED_TEXT_BYTES, OPENAI_MAX_SSE_EVENTS,
    OPENAI_MAX_SSE_FRAME_BYTES, OPENAI_MAX_SSE_LINES, OPENAI_MAX_TRANSPORT_CHUNKS,
    OpenAiHttpTransport, OpenAiTransport, OpenAiTransportError, OpenAiTransportPolicy,
    OpenAiTransportRequest, OpenAiTransportResponse,
};

use sse::decode_transport_response;
