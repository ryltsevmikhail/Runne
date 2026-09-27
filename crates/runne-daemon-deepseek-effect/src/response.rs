use std::collections::VecDeque;

use runne_provider::{DispatchAttemptId, DispatchError, ProviderStreamId};
use runne_provider_deepseek::{DeepSeekTransportResponse, decode_transport_response};

use crate::{Sender, diagnostics::DeepSeekEffectDiagnostic as Diagnostic};

impl<C> Sender<C> {
    pub(super) fn store_response(
        &self,
        attempt: DispatchAttemptId,
        response: DeepSeekTransportResponse,
    ) -> Result<ProviderStreamId, DispatchError> {
        let events = match decode_transport_response(&response) {
            Ok(events) => {
                self.observe(Diagnostic::Decoded);
                events
            }
            Err(error) => {
                self.observe(Diagnostic::DecodeFailed(error));
                return Err(DispatchError::MaybeDispatched);
            }
        };
        let stream = ProviderStreamId::from_bytes(*attempt.as_bytes());
        let mut streams = match self.streams.lock() {
            Ok(streams) => streams,
            Err(_) => {
                self.observe(Diagnostic::StreamStoreFailed);
                return Err(DispatchError::MaybeDispatched);
            }
        };
        streams.insert(stream, VecDeque::from(events));
        drop(streams);
        self.observe(Diagnostic::StreamStored);
        Ok(stream)
    }
}
