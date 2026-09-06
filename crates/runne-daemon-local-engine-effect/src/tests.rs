//! Isolated effect tests: binding to the `local` provider, digest
//! version policy, deterministic stream events, and cancel
//! pass-through.

use super::Sender;
use crate::engine::deterministic_events;
use crate::production;
use runne_provider::{
    CancelDisposition, CancelRequest, PrepareError, ProviderCall, ProviderCallDigestVersion,
    ProviderId, ProviderPort, ProviderStreamEventKind, ProviderStreamId,
    ProviderTerminalDisposition, ProviderUsage,
};

fn call() -> ProviderCall {
    let model_ref =
        runne_provider::ModelRef::new(ProviderId::new("local").expect("provider id"), "m1", "r1")
            .expect("model ref");
    ProviderCall::new(
        runne_provider::ProviderCallId::from_bytes([7; 16]),
        model_ref,
        [9; 32],
        256,
        serde_json::Value::Null,
    )
    .expect("call")
}

fn block<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime")
        .block_on(future)
}

#[test]
fn prepare_binds_to_the_local_provider() {
    let effect = production().expect("effect");
    ProviderPort::prepare(effect.as_ref(), &call()).expect("prepare");
}

#[test]
fn foreign_provider_binding_is_refused() {
    let model_ref =
        runne_provider::ModelRef::new(ProviderId::new("openai").expect("id"), "m1", "r1")
            .expect("model ref");
    let foreign = ProviderCall::new(
        runne_provider::ProviderCallId::from_bytes([7; 16]),
        model_ref,
        [9; 32],
        256,
        serde_json::Value::Null,
    )
    .expect("call");
    let effect = production().expect("effect");
    assert!(matches!(
        ProviderPort::prepare(effect.as_ref(), &foreign),
        Err(PrepareError::Render(_))
    ));
}

#[test]
fn unsupported_digest_version_refuses() {
    let effect = production().expect("effect");
    let err = ProviderPort::prepare_for_digest_version(
        effect.as_ref(),
        &call(),
        ProviderCallDigestVersion::V1,
    )
    .expect_err("unsupported");
    assert!(matches!(err, PrepareError::UnsupportedDigestVersion(_)));
}

/// Full compatibility cycle: staged events stream strictly from zero
/// and terminate Completed.
/// Full compatibility cycle: staged events stream strictly from zero
/// and terminate Completed (the store CAS owns receipts in production;
/// here the staged queue is filled through the crate-internal path).
#[test]
fn events_stream_from_zero_and_terminate_completed() {
    let sender = Sender::new();
    let stream = sender
        .store_events(
            runne_provider::DispatchAttemptId::from_bytes([3; 16]),
            deterministic_events().expect("events"),
        )
        .expect("store");
    let mut seq = 0u64;
    block(async move {
        for expected_kind in [
            ProviderStreamEventKind::Started,
            ProviderStreamEventKind::TextDelta {
                text: crate::engine::LOCAL_ENGINE_RESPONSE.to_owned(),
            },
            ProviderStreamEventKind::Usage {
                usage: ProviderUsage::new(1, 1, 0, 0).expect("usage"),
            },
            ProviderStreamEventKind::Finished {
                disposition: ProviderTerminalDisposition::Completed,
                reason: runne_provider::ProviderFinishReason::Stop,
            },
        ] {
            let expected = ProviderStreamEventKind::clone(&expected_kind);
            let item = ProviderPort::next(&sender, &stream, runne_provider::StreamCursor::new(seq))
                .await
                .expect("next");
            assert_eq!(item.event().sequence(), seq);
            assert_eq!(item.event().kind(), &expected);
            seq += 1;
        }
    });
}

#[test]
fn cancel_passes_through() {
    let effect = production().expect("effect");
    let disposition = block(async {
        ProviderPort::cancel(
            effect.as_ref(),
            CancelRequest::new(ProviderStreamId::from_bytes([3; 16])),
        )
        .await
        .expect("cancel")
    });
    assert_eq!(disposition, CancelDisposition::Requested);
}
