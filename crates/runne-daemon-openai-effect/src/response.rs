use std::collections::VecDeque;

use runne_provider::{DispatchAttemptId, DispatchError, ProviderStreamEvent, ProviderStreamId};
use runne_provider_openai::{
    OpenAiTransportResponse, decode_tool_transport_response, decode_transport_response,
};

use crate::Sender;

impl<C> Sender<C> {
    pub(super) fn store_response(
        &self,
        attempt: DispatchAttemptId,
        response: OpenAiTransportResponse,
        tool_mode: bool,
    ) -> Result<ProviderStreamId, DispatchError> {
        let events = if tool_mode {
            let profile = self
                .tool_profile
                .as_ref()
                .ok_or(DispatchError::MaybeDispatched)?;
            decode_tool_transport_response(&response, profile)
        } else {
            decode_transport_response(&response)
        }
        .map_err(|_| DispatchError::MaybeDispatched)?;
        self.store_events(attempt, events)
    }

    pub(super) fn store_events(
        &self,
        attempt: DispatchAttemptId,
        events: Vec<ProviderStreamEvent>,
    ) -> Result<ProviderStreamId, DispatchError> {
        let stream = ProviderStreamId::from_bytes(*attempt.as_bytes());
        self.streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?
            .insert(stream, VecDeque::from(events));
        Ok(stream)
    }
}
