fn operational_telemetry_schema() -> Value {
    let nullable_u64 = || json!({"oneOf": [telemetry_u64_schema(), {"type": "null"}]});
    let nullable_ref = |name: &str| {
        json!({"oneOf": [{"$ref": format!("#/$defs/{name}")}, {"type": "null"}]})
    };
    let definitions = json!({
        "accounting": closed_object(
            json!({"costMicroUsd": {"$ref": "#/$defs/budget"}, "tokens": {"$ref": "#/$defs/budget"}}),
            &["costMicroUsd", "tokens"],
        ),
        "budget": closed_object(
            json!({"limit": telemetry_u64_schema(), "remaining": telemetry_u64_schema(), "reserved": telemetry_u64_schema(), "settled": telemetry_u64_schema()}),
            &["limit", "remaining", "reserved", "settled"],
        ),
        "durable": durable_telemetry_schema(&nullable_ref, &nullable_u64),
        "expiryAggregate": closed_object(
            json!({"activeCount": telemetry_u64_schema(), "expiredActiveCount": telemetry_u64_schema(), "nearestUnexpiredExpiryUnixSeconds": nullable_u64()}),
            &["activeCount", "expiredActiveCount", "nearestUnexpiredExpiryUnixSeconds"],
        ),
        "recoveryTransient": recovery_transient_schema(&nullable_u64),
        "sectionMeta": section_meta_schema(),
    });
    let mut schema = closed_object(
        json!({
            "durable": {"$ref": "#/$defs/durable"}, "launchGeneration": positive_telemetry_u64_schema(),
            "observedAtUnixSeconds": telemetry_u64_schema(), "recoveryTransient": {"$ref": "#/$defs/recoveryTransient"},
            "schemaVersion": {"const": 1, "type": "integer"},
        }),
        &["durable", "launchGeneration", "observedAtUnixSeconds", "recoveryTransient", "schemaVersion"],
    );
    let object = schema.as_object_mut().unwrap();
    object.insert("$defs".to_owned(), definitions);
    object.insert("$id".to_owned(), json!("gocode://schemas/operational-telemetry-v1"));
    object.insert("$schema".to_owned(), json!(DRAFT_2020_12));
    object.insert("title".to_owned(), json!("Operational Telemetry V1"));
    schema
}

fn section_meta_schema() -> Value {
    let mut schema = closed_object(
        json!({
            "completeness": enum_schema(&["complete", "partial", "unavailable"]),
            "freshness": enum_schema(&["observed_in_current_cycle", "unavailable"]),
            "observedAtUnixSeconds": telemetry_u64_schema(),
        }),
        &["completeness", "freshness", "observedAtUnixSeconds"],
    );
    schema.as_object_mut().unwrap().insert(
        "oneOf".to_owned(),
        json!([
            meta_pair("observed_in_current_cycle", "complete"),
            meta_pair("observed_in_current_cycle", "partial"),
            meta_pair("unavailable", "unavailable"),
        ]),
    );
    schema
}

fn durable_telemetry_schema(nullable_ref: &impl Fn(&str) -> Value, nullable_u64: &impl Fn() -> Value) -> Value {
    let mut schema = closed_object(
        json!({
            "accounting": nullable_ref("accounting"), "committedProviderEffects": nullable_ref("expiryAggregate"),
            "meta": {"$ref": "#/$defs/sectionMeta"}, "providerApprovalLease": nullable_ref("expiryAggregate"),
            "providerEffectAuthorities": nullable_ref("expiryAggregate"), "uncertainAttempts": nullable_u64(),
        }),
        &["accounting", "committedProviderEffects", "meta", "providerApprovalLease", "providerEffectAuthorities", "uncertainAttempts"],
    );
    schema.as_object_mut().unwrap().insert(
        "allOf".to_owned(),
        json!([
            completeness_rule("complete", options_not_null()),
            completeness_rule("partial", partial_options()),
            completeness_rule("unavailable", options_null()),
        ]),
    );
    schema
}

fn recovery_transient_schema(nullable_u64: &impl Fn() -> Value) -> Value {
    let mut schema = closed_object(
        json!({
            "counterSaturated": {"type": "boolean"}, "droppedEventCount": telemetry_u64_schema(),
            "meta": {"$ref": "#/$defs/sectionMeta"}, "observedOutboxRecoveriesInGeneration": nullable_u64(),
            "status": enum_schema(&["lower_bound_since_launch", "truncated_lower_bound_since_launch", "unavailable"]),
        }),
        &["counterSaturated", "droppedEventCount", "meta", "observedOutboxRecoveriesInGeneration", "status"],
    );
    schema.as_object_mut().unwrap().insert(
        "allOf".to_owned(),
        json!([saturation_rule()]),
    );
    schema.as_object_mut().unwrap().insert(
        "oneOf".to_owned(),
        json!([
            recovery_variant("lower_bound_since_launch", "observed_in_current_cycle", "complete", json!({"counterSaturated": {"const": false}, "droppedEventCount": {"const": 0}, "observedOutboxRecoveriesInGeneration": {"not": {"type": "null"}}})),
            recovery_variant("truncated_lower_bound_since_launch", "observed_in_current_cycle", "partial", json!({"droppedEventCount": {"minimum": 1}, "observedOutboxRecoveriesInGeneration": {"not": {"type": "null"}}})),
            recovery_variant("unavailable", "unavailable", "unavailable", json!({"observedOutboxRecoveriesInGeneration": {"type": "null"}})),
        ]),
    );
    schema
}

fn meta_pair(freshness: &str, completeness: &str) -> Value {
    json!({"properties": {"freshness": {"const": freshness}, "completeness": {"const": completeness}}})
}

fn completeness_rule(completeness: &str, then: Value) -> Value {
    json!({"if": {"properties": {"meta": {"properties": {"completeness": {"const": completeness}}}}}, "then": then})
}

fn options_not_null() -> Value {
    json!({"properties": {"accounting": {"not": {"type": "null"}}, "committedProviderEffects": {"not": {"type": "null"}}, "providerApprovalLease": {"not": {"type": "null"}}, "providerEffectAuthorities": {"not": {"type": "null"}}, "uncertainAttempts": {"not": {"type": "null"}}}})
}

fn options_null() -> Value {
    json!({"properties": {"accounting": {"type": "null"}, "committedProviderEffects": {"type": "null"}, "providerApprovalLease": {"type": "null"}, "providerEffectAuthorities": {"type": "null"}, "uncertainAttempts": {"type": "null"}}})
}

fn partial_options() -> Value {
    let present = json!({"not": {"type": "null"}});
    let absent = json!({"type": "null"});
    json!({"allOf": [
        {"anyOf": option_properties(&present)},
        {"anyOf": option_properties(&absent)},
    ]})
}

fn option_properties(value: &Value) -> Vec<Value> {
    ["accounting", "committedProviderEffects", "providerApprovalLease", "providerEffectAuthorities", "uncertainAttempts"]
        .into_iter()
        .map(|name| json!({"properties": {name: value}}))
        .collect()
}

fn saturation_rule() -> Value {
    json!({"if": {"properties": {"droppedEventCount": {"const": u64::MAX}}}, "then": {"properties": {"counterSaturated": {"const": true}}}, "else": {"properties": {"counterSaturated": {"const": false}}}})
}

fn recovery_variant(status: &str, freshness: &str, completeness: &str, properties: Value) -> Value {
    let mut properties = properties.as_object().unwrap().clone();
    properties.insert("status".to_owned(), json!({"const": status}));
    properties.insert("meta".to_owned(), meta_pair(freshness, completeness));
    json!({"properties": properties})
}
