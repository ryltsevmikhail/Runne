#[test]
fn operational_telemetry_schema_enforces_meta_durable_and_recovery_variants() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let schema: Value = serde_json::from_slice(
        &fs::read(output.path().join("schemas/operational-telemetry-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let golden: Value = serde_json::from_slice(
        &fs::read(output.path().join("golden/operational-telemetry.json")).unwrap(),
    )
    .unwrap();
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap();

    for (freshness, completeness) in [
        ("unavailable", "complete"),
        ("observed_in_current_cycle", "unavailable"),
    ] {
        let mut fixture = golden.clone();
        *fixture.pointer_mut("/durable/meta/freshness").unwrap() = serde_json::json!(freshness);
        *fixture.pointer_mut("/durable/meta/completeness").unwrap() =
            serde_json::json!(completeness);
        assert_rejected(&validator, &fixture);
    }

    let mut complete_with_null = golden.clone();
    *complete_with_null.pointer_mut("/durable/accounting").unwrap() = Value::Null;
    assert_rejected(&validator, &complete_with_null);

    let mut partial_all_some = golden.clone();
    *partial_all_some
        .pointer_mut("/durable/meta/completeness")
        .unwrap() = serde_json::json!("partial");
    assert_rejected(&validator, &partial_all_some);

    let mut partial_all_none = partial_all_some.clone();
    set_durable_options_null(&mut partial_all_none);
    assert_rejected(&validator, &partial_all_none);

    let mut unavailable_with_some = golden.clone();
    set_durable_options_null(&mut unavailable_with_some);
    *unavailable_with_some
        .pointer_mut("/durable/meta/freshness")
        .unwrap() = serde_json::json!("unavailable");
    *unavailable_with_some
        .pointer_mut("/durable/meta/completeness")
        .unwrap() = serde_json::json!("unavailable");
    *unavailable_with_some
        .pointer_mut("/durable/accounting")
        .unwrap() = golden["durable"]["accounting"].clone();
    assert_rejected(&validator, &unavailable_with_some);

    assert!(validator.is_valid(&recovery_truncated(&golden, 1, false)));
    assert!(validator.is_valid(&recovery_truncated(&golden, u64::MAX, true)));
    assert!(validator.is_valid(&recovery_unavailable(&golden)));

    let mut lower_bound_drop = golden.clone();
    *lower_bound_drop
        .pointer_mut("/recoveryTransient/droppedEventCount")
        .unwrap() = serde_json::json!(1);
    assert_rejected(&validator, &lower_bound_drop);
    assert_rejected(&validator, &recovery_truncated(&golden, 0, false));
    assert_rejected(&validator, &recovery_truncated(&golden, u64::MAX, false));
    assert_rejected(&validator, &recovery_truncated(&golden, 1, true));

    let mut unavailable_with_count = recovery_unavailable(&golden);
    *unavailable_with_count
        .pointer_mut("/recoveryTransient/observedOutboxRecoveriesInGeneration")
        .unwrap() = serde_json::json!(0);
    assert_rejected(&validator, &unavailable_with_count);
}

#[test]
fn telemetry_openapi_uses_the_exact_session_authorization_scheme() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let openapi: Value =
        serde_json::from_slice(&fs::read(output.path().join("openapi.json")).unwrap()).unwrap();
    assert_eq!(
        openapi["components"]["securitySchemes"]["sessionAuth"],
        serde_json::json!({"scheme": "RunneSession", "type": "http"})
    );
    assert_eq!(
        openapi["paths"]["/v1/runtime/operational-telemetry"]["get"]["security"],
        serde_json::json!([{"sessionAuth": []}])
    );
}

fn set_durable_options_null(fixture: &mut Value) {
    for path in [
        "/durable/accounting",
        "/durable/providerEffectAuthorities",
        "/durable/providerApprovalLease",
        "/durable/committedProviderEffects",
        "/durable/uncertainAttempts",
    ] {
        *fixture.pointer_mut(path).unwrap() = Value::Null;
    }
}

fn recovery_truncated(golden: &Value, dropped: u64, saturated: bool) -> Value {
    let mut fixture = golden.clone();
    *fixture.pointer_mut("/recoveryTransient/status").unwrap() =
        serde_json::json!("truncated_lower_bound_since_launch");
    *fixture
        .pointer_mut("/recoveryTransient/droppedEventCount")
        .unwrap() = serde_json::json!(dropped);
    *fixture
        .pointer_mut("/recoveryTransient/counterSaturated")
        .unwrap() = serde_json::json!(saturated);
    *fixture
        .pointer_mut("/recoveryTransient/meta/completeness")
        .unwrap() = serde_json::json!("partial");
    fixture
}

fn recovery_unavailable(golden: &Value) -> Value {
    let mut fixture = golden.clone();
    *fixture.pointer_mut("/recoveryTransient/status").unwrap() =
        serde_json::json!("unavailable");
    *fixture
        .pointer_mut("/recoveryTransient/observedOutboxRecoveriesInGeneration")
        .unwrap() = Value::Null;
    *fixture
        .pointer_mut("/recoveryTransient/meta/freshness")
        .unwrap() = serde_json::json!("unavailable");
    *fixture
        .pointer_mut("/recoveryTransient/meta/completeness")
        .unwrap() = serde_json::json!("unavailable");
    fixture
}

fn assert_rejected(validator: &JSONSchema, fixture: &Value) {
    assert!(!validator.is_valid(fixture), "fixture must be rejected: {fixture}");
}
