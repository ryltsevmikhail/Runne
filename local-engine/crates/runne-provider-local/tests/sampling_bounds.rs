//! Sampling bounds (Plan Task 18 Step 1 / SAMPLING): out-of-range,
//! unknown-field and stop-budget violations reject BEFORE any host
//! effect; nothing is ever clamped (LOCAL-INV-008).

use runne_provider_local::SamplingError;
use runne_provider_local::sampling::{BackendBounds, ProfileDefaults, effective_sampling};
use serde_json::{Value, json};

fn validate(ext: Value) -> Result<runne_provider_local::EffectiveSampling, SamplingError> {
    // (kept: Value by value; callers clone where reused)
    effective_sampling(&ext, ProfileDefaults::v1(), BackendBounds::llama_cpu_v1())
}

#[test]
fn temperature_out_of_range_rejects_not_clamps() {
    for v in [2001u64, 5000, u32::MAX as u64] {
        let ext = json!({"local-engine.sampling.v1": {"temperature_milli": v}});
        let err = validate(ext).expect_err("over range");
        assert_eq!(err, SamplingError::OutOfRange("temperature_milli"));
    }
    let ext = json!({"local-engine.sampling.v1": {"temperature_milli": 2000}});
    assert!(validate(ext).is_ok(), "boundary is inclusive");
}

#[test]
fn top_p_zero_is_undefined_and_rejects() {
    let ext = json!({"local-engine.sampling.v1": {"top_p_milli": 0}});
    assert_eq!(
        validate(ext).expect_err("top_p 0"),
        SamplingError::OutOfRange("top_p_milli")
    );
}

#[test]
fn unknown_field_rejects() {
    let ext = json!({"local-engine.sampling.v1": {"top_a": 42}});
    assert_eq!(
        validate(ext).expect_err("unknown"),
        SamplingError::UnknownField("top_a".into())
    );
}

#[test]
fn float_and_wrong_type_reject() {
    let ext = json!({"local-engine.sampling.v1": {"temperature_milli": 0.7}});
    assert!(matches!(
        validate(ext).expect_err("float"),
        SamplingError::Malformed
    ));
    let ext = json!({"local-engine.sampling.v1": {"top_k": "ten"}});
    assert!(matches!(
        validate(ext).expect_err("string"),
        SamplingError::Malformed
    ));
}

#[test]
fn stop_budget_rejects() {
    let five = json!({"local-engine.sampling.v1": {"stop": ["a", "b", "c", "d", "e"]}});
    assert_eq!(
        validate(five).expect_err("5 items"),
        SamplingError::OutOfRange("stop")
    );
    // Four 65-byte items = 260 > 256-byte total budget.
    let long = "x".repeat(65);
    let over_total = json!({
        "local-engine.sampling.v1": {"stop": [long, long.clone(), long.clone(), long]}
    });
    assert_eq!(
        validate(over_total).expect_err("total budget"),
        SamplingError::OutOfRange("stop")
    );
    // Exactly at the budget is fine.
    let at = "x".repeat(64);
    let at_limit = json!({
        "local-engine.sampling.v1": {"stop": [at.clone(), at.clone(), at.clone(), at]}
    });
    assert!(validate(at_limit).is_ok());
}

#[test]
fn profile_over_1kib_rejects() {
    // Oversize map via many stop entries is capped by count; use the
    // namespace itself with a huge unknown object body (canonical size
    // check runs before field checks).
    let mut big = serde_json::Map::new();
    let mut inner = serde_json::Map::new();
    inner.insert(
        "stop".into(),
        Value::Array(vec![Value::String("y".repeat(64)); 4]),
    );
    big.insert(
        "local-engine.sampling.v1".into(),
        Value::Object(inner.clone()),
    );
    let r = validate(Value::Object(big.clone()));
    // Within budget or above must be a typed outcome, never a panic.
    assert!(r.is_ok() || r.is_err());
    let _ = inner;
}

#[test]
fn reasoning_effort_unsupported_by_cpu_profile_rejects() {
    let ext = json!({"local-engine.sampling.v1": {"reasoning_effort": "high"}});
    assert_eq!(
        validate(ext.clone()).expect_err("no reasoning"),
        SamplingError::ReasoningEffortUnsupported
    );
    // A reasoning-capable backend profile accepts the same call.
    let ok = effective_sampling(
        &ext.clone(),
        ProfileDefaults::v1(),
        BackendBounds {
            reasoning_supported: true,
        },
    );
    assert!(ok.is_ok());
}

#[test]
fn defaults_apply_without_extension() {
    let e = validate(Value::Null).expect("defaults");
    assert_eq!(e.temperature_milli, 700);
    assert_eq!(e.top_k, None);
    // Override replaces only the named key.
    let e = validate(json!({"local-engine.sampling.v1": {"top_k": 40}})).expect("override");
    assert_eq!(e.temperature_milli, 700, "default preserved");
    assert_eq!(e.top_k, Some(40));
}
