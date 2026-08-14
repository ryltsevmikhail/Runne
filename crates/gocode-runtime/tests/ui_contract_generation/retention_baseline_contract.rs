#[test]
fn retention_baseline_v1_and_v2_are_closed_and_validate_their_goldens() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let replay: Value = serde_json::from_slice(
        &fs::read(output.path().join("schemas/replay-v1.schema.json")).unwrap(),
    )
    .unwrap();
    for (definition, golden_path) in [
        ("retentionGapResponse", "golden/replay-retention-gap.json"),
        (
            "retentionGapResponseV2",
            "golden/replay-retention-gap-v2.json",
        ),
    ] {
        assert_eq!(replay["$defs"][definition]["additionalProperties"], false);
        let schema = serde_json::json!({"$defs": replay["$defs"].clone(), "$ref": format!("#/$defs/{definition}")});
        let golden: Value =
            serde_json::from_slice(&fs::read(output.path().join(golden_path)).unwrap()).unwrap();
        assert!(
            JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .compile(&schema)
                .unwrap()
                .is_valid(&golden)
        );
    }
    let baseline = &replay["$defs"]["replayRetentionBaselineV2"];
    assert_eq!(baseline["additionalProperties"], false);
    assert_eq!(baseline["properties"]["schemaVersion"]["const"], 2);
    assert_eq!(
        baseline["properties"]["promotionProjectionBytes"]["maxLength"],
        699_051
    );
    let encoded_limit = 699_051;
    let schema = serde_json::json!({
        "$defs": replay["$defs"].clone(),
        "$ref": "#/$defs/replayRetentionBaselineV2"
    });
    let compiled = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    let mut boundary = serde_json::from_slice::<Value>(
        &fs::read(output.path().join("golden/replay-retention-gap-v2.json")).unwrap(),
    )
    .unwrap()["baseline"]
        .clone();
    boundary["promotionProjectionBytes"] = Value::String("A".repeat(encoded_limit));
    assert!(compiled.is_valid(&boundary));
    boundary["promotionProjectionBytes"] = Value::String("A".repeat(encoded_limit + 1));
    assert!(!compiled.is_valid(&boundary));
}

#[test]
fn replay_resume_contract_is_authenticated_bounded_and_no_store() {
    let output = tempfile::tempdir().unwrap();
    generate_ui_contract(output.path()).unwrap();
    let replay: Value = serde_json::from_slice(
        &fs::read(output.path().join("schemas/replay-v1.schema.json")).unwrap(),
    )
    .unwrap();
    let golden: Value = serde_json::from_slice(
        &fs::read(output.path().join("golden/replay-resume-v2.json")).unwrap(),
    )
    .unwrap();
    for (definition, value) in [
        ("resumeFromBaselineRequestV2", &golden["request"]),
        ("resumeFromBaselineResponseV2", &golden["acceptedResponse"]),
    ] {
        let schema = serde_json::json!({"$defs": replay["$defs"].clone(), "$ref": format!("#/$defs/{definition}")});
        assert!(
            JSONSchema::options()
                .with_draft(Draft::Draft202012)
                .compile(&schema)
                .unwrap()
                .is_valid(value)
        );
    }
    let openapi: Value =
        serde_json::from_slice(&fs::read(output.path().join("openapi.json")).unwrap()).unwrap();
    let open_gap = &openapi["paths"]["/v1/replay/open-session"]["post"]["responses"]["410"];
    assert_eq!(
        open_gap["content"]["application/json"]["schema"]["oneOf"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    let resume = &openapi["paths"]["/v1/replay/resume-from-baseline"]["post"];
    assert_eq!(resume["security"], serde_json::json!([{"sessionAuth": []}]));
    assert_eq!(resume["requestBody"]["x-gocode-maxBodyBytes"], 1_048_576);
    for status in ["200", "401", "410"] {
        assert_eq!(
            resume["responses"][status]["headers"]["Cache-Control"]["required"],
            true
        );
        assert_eq!(
            resume["responses"][status]["headers"]["Cache-Control"]["schema"]["const"],
            "no-store"
        );
        assert_eq!(
            resume["responses"][status]["headers"]["X-Request-Id"]["required"],
            true
        );
    }
}
