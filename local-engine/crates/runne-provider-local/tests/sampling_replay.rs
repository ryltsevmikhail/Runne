//! Sampling replay identity (Plan Task 18 Step 2 / SAMPLING §Identity):
//! same inputs → same effective digest and attempt identity; changed
//! sampling → new attempt identity (different render digest).

mod common;

use common::{AllowPermit, SettlementPort, adapter, admit_model, call};
use runne_provider_local::port::ProviderPort;
use serde_json::json;

fn prepare_with(extension: serde_json::Value) -> runne_provider_local::PreparedRequest {
    let dir = tempfile::tempdir().expect("dir");
    let fixture = admit_model(dir.path());
    let a = adapter(dir.path(), AllowPermit, SettlementPort::default(), &fixture);
    let mut c = call(&fixture.manifest_digest, "hello");
    c.extension = extension;
    a.prepare(&c).expect("prepare")
}

#[test]
fn same_inputs_same_effective_digest() {
    let p1 = prepare_with(serde_json::Value::Null);
    let p2 = prepare_with(serde_json::Value::Null);
    assert_eq!(p1.sampling_digest, p2.sampling_digest);
    assert_eq!(p1.render_digest, p2.render_digest);

    let ext = json!({"local-engine.sampling.v1": {"temperature_milli": 350, "seed": 7}});
    let p3 = prepare_with(ext.clone());
    let p4 = prepare_with(ext);
    assert_eq!(p3.sampling_digest, p4.sampling_digest);
    assert_eq!(p3.render_digest, p4.render_digest);
}

#[test]
fn changed_sampling_is_a_new_attempt() {
    let base = prepare_with(serde_json::Value::Null);
    let hot = prepare_with(json!({"local-engine.sampling.v1": {"temperature_milli": 350}}));
    let hotter = prepare_with(json!({"local-engine.sampling.v1": {"temperature_milli": 351}}));
    assert_ne!(base.sampling_digest, hot.sampling_digest);
    assert_ne!(base.render_digest, hot.render_digest);
    assert_ne!(hot.sampling_digest, hotter.sampling_digest);
    assert_ne!(hot.render_digest, hotter.render_digest);
}

#[test]
fn semantically_equal_maps_share_identity() {
    // stop: [] is the disabled default — same effective map.
    let p1 = prepare_with(serde_json::Value::Null);
    let p2 = prepare_with(json!({"local-engine.sampling.v1": {"stop": []}}));
    assert_eq!(p1.sampling_digest, p2.sampling_digest);
    assert_eq!(p1.render_digest, p2.render_digest);
}
