use runne_provider::{ProviderStreamEvent, ProviderStreamEventKind};
use thiserror::Error;

use crate::sse::SseFramer;

const MAX_EVENTS: usize = 16_384;
const MAX_TEXT_BYTES: usize = 65_536;

#[derive(Debug)]
pub(super) struct State {
    pub(super) framer: SseFramer,
    pub(super) stage: Stage,
    pub(super) model: Option<String>,
    pub(super) model_alias: Option<String>,
    pub(super) response_id: Option<String>,
    pub(super) usage: Option<runne_provider::ProviderUsage>,
    pub(super) usage_parts: Option<(u64, u64, u64, u64)>,
    pub(super) stop: Option<(
        runne_provider::ProviderTerminalDisposition,
        runne_provider::ProviderFinishReason,
    )>,
    pub(super) terminal: bool,
    pub(super) text_bytes: usize,
    pub(super) events: usize,
    pub(super) normalized: Vec<ProviderStreamEvent>,
    pub(super) active_block: Option<BlockKind>,
    pub(super) next_block_index: u64,
}

impl State {
    pub(super) fn new(max_frame: usize, model: Option<&str>, model_alias: Option<&str>) -> Self {
        Self {
            framer: SseFramer::new(max_frame),
            stage: Stage::Start,
            model: model.map(str::to_owned),
            model_alias: model_alias.map(str::to_owned),
            response_id: None,
            usage: None,
            usage_parts: None,
            stop: None,
            terminal: false,
            text_bytes: 0,
            events: 0,
            normalized: Vec::new(),
            active_block: None,
            next_block_index: 0,
        }
    }
    pub(super) fn push_event(
        &mut self,
        kind: ProviderStreamEventKind,
    ) -> Result<(), WireDecodeError> {
        self.events = self
            .events
            .checked_add(1)
            .filter(|value| *value <= MAX_EVENTS)
            .ok_or(WireDecodeError::BoundExceeded)?;
        let sequence =
            u64::try_from(self.normalized.len()).map_err(|_| WireDecodeError::BoundExceeded)?;
        self.normalized.push(
            ProviderStreamEvent::new(sequence, kind).map_err(|_| WireDecodeError::Malformed)?,
        );
        Ok(())
    }
    pub(super) fn text(&mut self, text: &str) -> Result<(), WireDecodeError> {
        if text.is_empty() {
            return Ok(());
        }
        self.text_bytes = self
            .text_bytes
            .checked_add(text.len())
            .filter(|value| *value <= MAX_TEXT_BYTES)
            .ok_or(WireDecodeError::BoundExceeded)?;
        self.push_event(ProviderStreamEventKind::TextDelta {
            text: text.to_owned(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BlockKind {
    Text,
    Thinking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    Start,
    Block,
    Delta,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum WireDecodeError {
    #[error("malformed")]
    Malformed,
    #[error("bound")]
    BoundExceeded,
    #[error("usage")]
    InvalidUsage,
    #[error("unsupported")]
    UnsupportedContent,
}
