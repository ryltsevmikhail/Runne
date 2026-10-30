use std::collections::VecDeque;

use runne_provider::{DispatchAttemptId, DispatchError, ProviderStreamId};
use runne_provider_deepseek::DeepSeekTransportResponse;
#[cfg(not(feature = "linux-native-enrollment-qualification"))]
use runne_provider_deepseek::decode_transport_response;

use crate::{Sender, diagnostics::DeepSeekEffectDiagnostic as Diagnostic};

impl<C> Sender<C> {
    pub(super) fn store_response(
        &self,
        attempt: DispatchAttemptId,
        response: DeepSeekTransportResponse,
    ) -> Result<ProviderStreamId, DispatchError> {
        #[cfg(feature = "linux-native-enrollment-qualification")]
        let (decoded, diagnostic) = if let Some(profile) = &self.tool_profile {
            (
                runne_provider_deepseek::decode_tool_transport_response(&response, profile),
                None,
            )
        } else {
            runne_provider_deepseek::decode_transport_response_with_diagnostic(&response)
        };
        #[cfg(not(feature = "linux-native-enrollment-qualification"))]
        let decoded = if let Some(profile) = &self.tool_profile {
            runne_provider_deepseek::decode_tool_transport_response(&response, profile)
        } else {
            decode_transport_response(&response)
        };
        let events = match decoded {
            Ok(events) => {
                self.observe(Diagnostic::Decoded);
                events
            }
            Err(error) => {
                #[cfg(feature = "linux-native-enrollment-qualification")]
                if let Some(detail) = diagnostic {
                    self.observe(Diagnostic::DecodeDetail { error, detail });
                } else {
                    self.observe(Diagnostic::DecodeFailed(error));
                }
                #[cfg(not(feature = "linux-native-enrollment-qualification"))]
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
