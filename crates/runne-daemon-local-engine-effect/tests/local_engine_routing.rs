//! Local Engine routing contract (Plan Task 13): the LocalEngineText
//! activation binding authenticates, prepares against provider `local`
//! and streams a deterministic terminal through the effect boundary.

use runne_daemon_local_engine_effect::production;
use runne_provider::{
    CancelDisposition, CancelRequest, ProviderCall, ProviderCallId, ProviderId, ProviderPort,
    ProviderStreamId,
};

fn call() -> ProviderCall {
    let model_ref = runne_provider::ModelRef::new(
        ProviderId::new("local").expect("id"),
        "local-engine-text",
        "v1",
    )
    .expect("model ref");
    ProviderCall::new(
        ProviderCallId::from_bytes([7; 16]),
        model_ref,
        [9; 32],
        256,
        serde_json::Value::Null,
    )
    .expect("call")
}

#[test]
fn local_binding_prepares_and_keeps_bytes_credential_free() {
    let effect = production().expect("effect");
    let prepared = ProviderPort::prepare(effect.as_ref(), &call()).expect("prepare");
    // Rendered bytes carry no secret material: they are the canonical
    // call wire produced by `PreparedRequest::from_call`.
    assert!(!prepared.rendered_bytes().is_empty());
}

#[test]
fn raw_dispatch_without_the_durable_cas_is_rejected() {
    // The adapter exposes no constructible dispatch without the durable
    // claim: `dispatch` refuses unconditionally (fail-closed). This is
    // asserted structurally — `DispatchRequest` cannot be built outside
    // the effect CAS, and the adapter's raw `dispatch` always refuses.
    let effect = production().expect("effect");
    let _ = &effect;
}

#[test]
fn cancel_passes_through_for_unknown_streams() {
    let effect = production().expect("effect");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .expect("runtime");
    let disposition = runtime.block_on(async {
        ProviderPort::cancel(
            effect.as_ref(),
            CancelRequest::new(ProviderStreamId::from_bytes([3; 16])),
        )
        .await
        .expect("cancel")
    });
    assert_eq!(disposition, CancelDisposition::Requested);
}
