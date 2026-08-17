use std::collections::VecDeque;

use gocode_provider::{DispatchAttemptId, DispatchError, ProviderStreamId};
use gocode_provider_deepseek::{DeepSeekTransportResponse, decode_transport_response};

use crate::Sender;

impl<C> Sender<C> {
    pub(super) fn store_response(
        &self,
        attempt: DispatchAttemptId,
        response: DeepSeekTransportResponse,
    ) -> Result<ProviderStreamId, DispatchError> {
        let events =
            decode_transport_response(&response).map_err(|_| DispatchError::MaybeDispatched)?;
        let stream = ProviderStreamId::from_bytes(*attempt.as_bytes());
        self.streams
            .lock()
            .map_err(|_| DispatchError::MaybeDispatched)?
            .insert(stream, VecDeque::from(events));
        Ok(stream)
    }
}
