use std::any::Any;

use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderPreEffectRejection, ProviderStreamId, ProviderStreamItem, ReconcileRequest,
    ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_store::provider::{
    CredentialDispatchBinding, ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect,
};

use crate::{NativeEffect, NativeWireProfile, is_terminal};

/// Staged credential-bearing state; it cannot be created by callers.
pub struct AuthorizedReady {
    pub(super) request: DispatchRequest,
    pub(super) credential: CredentialDispatchBinding,
}

impl ProviderReadyEffect for AuthorizedReady {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl ProviderPort for NativeEffect {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        match &self.profile {
            NativeWireProfile::Anthropic(profile) => prepare_anthropic(profile, call),
            NativeWireProfile::Gemini(profile) => prepare_gemini(profile, call),
        }
    }
    fn prepare_for_digest_version(
        &self,
        call: &ProviderCall,
        version: ProviderCallDigestVersion,
    ) -> Result<PreparedRequest, PrepareError> {
        if version != ProviderCallDigestVersion::V2 {
            return Err(PrepareError::UnsupportedDigestVersion(version));
        }
        self.prepare(call)
    }
    fn dispatch(
        &self,
        _: DispatchRequest,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async {
            Err(DispatchError::RejectedBeforeEffect(
                ProviderPreEffectRejection::AdapterRejected,
            ))
        })
    }
    fn next<'a>(
        &'a self,
        stream: &'a ProviderStreamId,
        cursor: StreamCursor,
    ) -> ProviderFuture<'a, Result<ProviderStreamItem, StreamError>> {
        Box::pin(async move {
            let mut streams = self.streams.lock().map_err(|_| StreamError::NotFound)?;
            let key = *stream;
            let mut entry = streams.remove(&key).ok_or(StreamError::NotFound)?;
            let Some(event) = entry.events.front() else {
                streams.insert(key, entry);
                return Err(StreamError::Closed);
            };
            if event.sequence() != cursor.sequence() {
                let actual = event.sequence();
                streams.insert(key, entry);
                return Err(StreamError::SequenceGap {
                    expected: cursor.sequence(),
                    actual,
                });
            }
            let event = entry.events.pop_front().ok_or(StreamError::Closed)?;
            let terminal = is_terminal(&event);
            let item = match ProviderStreamItem::from_event(event) {
                Ok(item) => item,
                Err(error) => {
                    streams.insert(key, entry);
                    return Err(error);
                }
            };
            if terminal {
                drop(entry);
            } else {
                streams.insert(key, entry);
            }
            Ok(item)
        })
    }
    fn cancel(
        &self,
        request: CancelRequest,
    ) -> ProviderFuture<'_, Result<CancelDisposition, DispatchError>> {
        Box::pin(async move {
            self.streams
                .lock()
                .map_err(|_| DispatchError::MaybeDispatched)?
                .remove(&request.stream_id());
            Ok(CancelDisposition::Requested)
        })
    }
    fn reconcile(
        &self,
        _: ReconcileRequest,
    ) -> ProviderFuture<'_, Result<ReconciliationDisposition, DispatchError>> {
        Box::pin(async { Ok(ReconciliationDisposition::Uncertain) })
    }
}

impl ProviderEffectPort for NativeEffect {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            Ok(Box::new(AuthorizedReady {
                request,
                credential,
            }) as Box<dyn ProviderReadyEffect>)
        })
    }
    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        Box::pin(async move {
            let ready = ready
                .into_any()
                .downcast::<AuthorizedReady>()
                .map_err(|_| DispatchError::MaybeDispatched)?;
            self.dispatch_authorized(*ready, receipt).await
        })
    }
}

pub fn prepare_anthropic(
    profile: &runne_provider_native_wire::AnthropicMessagesProfile,
    call: &ProviderCall,
) -> Result<PreparedRequest, PrepareError> {
    runne_provider_native_wire::AnthropicMessagesRenderer::new(profile.clone())
        .prepare(call)
        .map_err(|error| PrepareError::Render(error.to_string()))
}

pub fn prepare_gemini(
    profile: &runne_provider_native_wire::GeminiProfile,
    call: &ProviderCall,
) -> Result<PreparedRequest, PrepareError> {
    runne_provider_native_wire::GeminiRenderer::new(profile.clone())
        .prepare(call)
        .map_err(|error| PrepareError::Render(error.to_string()))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use runne_provider::{
        ProviderFinishReason, ProviderStreamEvent, ProviderStreamEventKind,
        ProviderTerminalDisposition, StreamCursor,
    };
    use runne_secure_store::{
        ProviderCredentialDispatchMaterializer, ProviderCredentialDispatchRead,
        ProviderCredentialMaterial, SecureStoreError,
    };

    use super::*;

    struct Deny;
    impl ProviderCredentialDispatchMaterializer for Deny {
        fn materialize_active(
            &self,
            _: ProviderCredentialDispatchRead<'_>,
        ) -> Result<ProviderCredentialMaterial, SecureStoreError> {
            Err(SecureStoreError::CredentialAccessDenied)
        }
    }

    #[tokio::test]
    async fn invalid_cursor_preserves_event_and_permit_until_terminal() {
        let profile = runne_provider_native_wire::NativeWireProfile::Anthropic(
            runne_provider_native_wire::AnthropicMessagesProfile::new(
                "anthropic",
                "native",
                "model",
                "rev",
                [1; 32],
                [2; 32],
                runne_provider_native_wire::WireLimits::new(1, 16, 32, 8, 128, 64).unwrap(),
            )
            .unwrap(),
        );
        let effect = crate::NativeEffect::new(
            profile,
            crate::TrustedNativeEndpoint::anthropic("https://api.anthropic.com").unwrap(),
            crate::NativeAuthDescriptor::AnthropicApiKey,
            Arc::new(Deny),
            crate::NativeEffectConfig {
                max_concurrent: 1,
                ..Default::default()
            },
        )
        .unwrap();
        let stream = runne_provider::ProviderStreamId::from_bytes([7; 16]);
        let events = vec![
            ProviderStreamEvent::new(0, ProviderStreamEventKind::Started).unwrap(),
            ProviderStreamEvent::new(
                1,
                ProviderStreamEventKind::Finished {
                    disposition: ProviderTerminalDisposition::Completed,
                    reason: ProviderFinishReason::Stop,
                },
            )
            .unwrap(),
        ];
        let permit = effect.permits.clone().try_acquire_owned().unwrap();
        effect.streams.lock().unwrap().insert(
            stream,
            crate::StreamEntry {
                events: events.into(),
                _permit: permit,
            },
        );
        assert_eq!(effect.permits.available_permits(), 0);
        assert!(matches!(
            effect.next(&stream, StreamCursor::new(1)).await,
            Err(StreamError::SequenceGap {
                expected: 1,
                actual: 0
            })
        ));
        assert!(effect.next(&stream, StreamCursor::new(0)).await.is_ok());
        assert_eq!(effect.permits.available_permits(), 0);
        assert!(effect.next(&stream, StreamCursor::new(1)).await.is_ok());
        assert_eq!(effect.permits.available_permits(), 1);
        assert!(effect.next(&stream, StreamCursor::new(2)).await.is_err());
        drop(effect);
    }
}
