#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Exact-profile `OpenAI` Responses text adapter contracts.

mod profile;
mod render;

pub use profile::{
    OPENAI_MODEL_ID, OPENAI_MODEL_REVISION, OPENAI_REQUEST_MODEL, OPENAI_RESPONSES_PROFILE_ID,
    OpenAiProfileError, OpenAiResponsesTextProfile,
};
pub use render::{OpenAiRenderError, OpenAiResponsesTextRenderer};
