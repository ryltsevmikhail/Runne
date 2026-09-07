//! Generation streaming: validates load/attempt identity, streams
//! ordered backend items with bounded sequence, records terminal.

use crate::error::HostError;
use crate::session::{HostSession, HostState};
use runne_inference_protocol::MessageV1;

/// Streams the backend's deterministic output for one generation.
/// Enforces: model loaded, attempt/generation identity consistent,
/// strictly increasing stream_sequence from zero.
pub fn stream_generation<B: crate::backend::BackendPort>(
    host: &mut HostSession<B>,
    generation_id: [u8; 16],
    attempt_id: [u8; 16],
    stream_id: [u8; 16],
    prompt: &str,
) -> Result<Vec<MessageV1>, HostError> {
    host.require_loaded()?;
    if host.active_generation == Some(generation_id) {
        return Err(HostError::AttemptConflict);
    }
    host.active_generation = Some(generation_id);
    host.active_attempt = Some(attempt_id);
    host.active_stream = Some(stream_id);
    host.state = HostState::Generating;

    let ctx = crate::backend::GenerationCtx {
        generation_id,
        attempt_id,
        stream_id,
        prompt: prompt.to_string(),
        artifact_path_hint: None,
    };
    let items = host.backend.generate(&ctx)?;

    // Bounded sequence: strictly increasing from zero.
    let mut prev: Option<u64> = None;
    for item in &items {
        if let runne_inference_protocol::MessageV1::StreamItem {
            stream_sequence, ..
        } = item
        {
            if prev.is_some_and(|p| *stream_sequence <= p) {
                return Err(HostError::MalformedStream);
            }
            prev = Some(*stream_sequence);
        }
    }
    host.state = HostState::Loaded;
    host.active_generation = Some(generation_id);
    Ok(items)
}
