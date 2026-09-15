use std::any::Any;

use runne_provider::{
    CancelDisposition, CancelRequest, DispatchError, DispatchRequest, PrepareError,
    PreparedRequest, ProviderCall, ProviderCallDigestVersion, ProviderFuture, ProviderPort,
    ProviderPreEffectRejection, ProviderStreamId, ProviderStreamItem, ReconcileRequest,
    ReconciliationDisposition, StreamCursor, StreamError,
};
use runne_store::provider::{ProviderEffectPort, ProviderEffectStartReceipt, ProviderReadyEffect};

use crate::{RadiusEffect, Ready, is_terminal};

impl ProviderReadyEffect for Ready {
    fn into_any(self: Box<Self>) -> Box<dyn Any + Send> {
        self
    }
}

impl ProviderPort for RadiusEffect {
    fn prepare(&self, call: &ProviderCall) -> Result<PreparedRequest, PrepareError> {
        self.renderer
            .prepare(call)
            .map_err(|error| PrepareError::Render(error.to_string()))
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

impl ProviderEffectPort for RadiusEffect {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: runne_store::provider::CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            Ok(Box::new(Ready {
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
                .downcast::<Ready>()
                .map_err(|_| DispatchError::MaybeDispatched)?;
            self.dispatch_ready(*ready, receipt).await
        })
    }
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
        let profile = runne_provider_radius::RadiusCatalog::from_json(
            br#"{"baseUrl":"https://radius.pi.dev","models":[{"id":"fixture-model","name":"Fixture","reasoning":false,"input":["text"],"contextWindow":4096,"maxTokens":512,"cost":{"input":0.000001,"output":0.000002,"cacheRead":0.000001,"cacheWrite":0.000001}}]}"#,
        )
        .unwrap()
        .select_with_accounting(
            "radius",
            "fixture-model",
            "pi/revision",
            runne_provider_radius::RadiusAccounting::Payg,
        )
        .unwrap();
        let effect = RadiusEffect::new(
            profile,
            crate::RadiusAuth::ApiKey,
            Arc::new(Deny),
            crate::RadiusEffectConfig {
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
    }
}
