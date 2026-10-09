use super::support::*;

fn duplicate_once(encoded: &str, marker: &str, replacement: &str) -> String {
    let duplicate = encoded.replacen(marker, replacement, 1);
    assert_ne!(
        duplicate, encoded,
        "duplicate fixture marker missing: {marker}"
    );
    duplicate
}

fn v2_committed_status() -> PermissionModeCommandStatusV3 {
    let history = PermissionModeHistoryV2::capture(&full_access_allow_status());
    PermissionModeCommandStatusV3::Committed {
        receipt: Box::new(PermissionModeChangeReceiptV3::V2 {
            receipt: v2_receipt(history),
        }),
    }
}

#[test]
fn v2_wire_requires_nullable_fields_and_rejects_unknown_fields() {
    let encoded = serde_json::to_value(full_access_allow_status()).expect("status JSON value");
    for field in ["containment", "expiresAtUnixMs"] {
        let mut missing = encoded.clone();
        let removed = missing
            .as_object_mut()
            .expect("status object")
            .remove(field);
        assert!(
            removed.is_some(),
            "required nullable status field missing: {field}"
        );
        let wire = serde_json::to_string(&missing).expect("missing-field JSON");
        assert!(
            serde_json::from_str::<PermissionModeStatusV2>(&wire).is_err(),
            "accepted missing nullable field {field}"
        );
    }

    let mut unknown = encoded.clone();
    assert!(unknown.get("unexpectedAuthority").is_none());
    unknown["unexpectedAuthority"] = serde_json::json!(true);
    assert_eq!(unknown["unexpectedAuthority"], serde_json::json!(true));
    let wire = serde_json::to_string(&unknown).expect("unknown-field JSON");
    assert!(serde_json::from_str::<PermissionModeStatusV2>(&wire).is_err());
}

#[test]
fn direct_wire_decode_rejects_duplicate_object_keys() {
    let encoded = serde_json::to_string(&full_access_allow_status()).expect("status JSON");
    let duplicate = duplicate_once(
        &encoded,
        "\"authorizationRevision\":8",
        "\"authorizationRevision\":8,\"authorizationRevision\":8",
    );
    assert!(
        serde_json::from_str::<PermissionModeStatusV2>(&duplicate).is_err(),
        "accepted duplicate status key"
    );

    let v1 = PermissionModeCommandStatusV3::Committed {
        receipt: Box::new(PermissionModeChangeReceiptV3::V1 {
            receipt: v1_receipt(),
        }),
    };
    let encoded = serde_json::to_string(&v1).expect("receipt union JSON");
    let duplicate = duplicate_once(
        &encoded,
        "\"version\":\"v1\"",
        "\"version\":\"v1\",\"version\":\"v1\"",
    );
    assert!(
        serde_json::from_str::<PermissionModeCommandStatusV3>(&duplicate).is_err(),
        "accepted duplicate receipt version"
    );
}

#[test]
fn raw_json_nested_duplicate_keys_are_rejected_at_every_contract_layer() {
    let encoded = serde_json::to_string(&full_access_allow_status()).expect("status JSON");
    for (marker, replacement) in [
        (
            "\"effective\":{\"state\":\"ready\"",
            "\"effective\":{\"state\":\"ready\",\"state\":\"ready\"",
        ),
        (
            "\"managedDecision\":\"allow\"",
            "\"managedDecision\":\"allow\",\"managedDecision\":\"allow\"",
        ),
        (
            "\"fsCreate\":",
            "\"fsRead\":{\"managedDecision\":\"allow\",\"presetBehavior\":\"noPresetPrompt\",\"enforcementAvailability\":{\"state\":\"native\"},\"disposition\":{\"state\":\"available\"}},\"fsCreate\":",
        ),
        (
            "\"filesystem\":{",
            "\"filesystem\":{\"posture\":\"broadSameUser\",\"rights\":[\"read\",\"create\",\"write\",\"delete\"]},\"filesystem\":{",
        ),
    ] {
        let duplicate = duplicate_once(&encoded, marker, replacement);
        assert!(
            serde_json::from_str::<PermissionModeStatusV2>(&duplicate).is_err(),
            "accepted duplicate nested status key from {marker}"
        );
    }

    let history = PermissionModeHistoryV2::capture(&full_access_allow_status());
    let history_json = serde_json::to_string(&history).expect("history JSON");
    let v2_wire = serde_json::to_string(&v2_committed_status()).expect("V3 V2 receipt JSON");
    let duplicate_history = duplicate_once(
        &v2_wire,
        "\"history\":{",
        &format!("\"history\":{},\"history\":{{", history_json),
    );
    assert!(
        serde_json::from_str::<PermissionModeCommandStatusV3>(&duplicate_history).is_err(),
        "accepted duplicate V2 receipt history key"
    );

    let duplicate_history_field = duplicate_once(
        &v2_wire,
        "\"history\":{\"selectedMode\":\"full_access\"",
        "\"history\":{\"selectedMode\":\"full_access\",\"selectedMode\":\"full_access\"",
    );
    assert!(
        serde_json::from_str::<PermissionModeCommandStatusV3>(&duplicate_history_field).is_err(),
        "accepted duplicate field inside V2 receipt history"
    );
}

#[test]
fn closed_enums_and_action_map_reject_unknown_variants_and_keys() {
    let base = serde_json::to_value(full_access_allow_status()).expect("status JSON value");

    let mut unknown_lifecycle = base.clone();
    unknown_lifecycle["lifecycle"] = serde_json::json!("futureLifecycle");
    assert_ne!(unknown_lifecycle, base);
    assert!(serde_json::from_value::<PermissionModeStatusV2>(unknown_lifecycle).is_err());

    let mut unknown_action = base.clone();
    assert!(base["effective"]["actionMap"].get("futureAction").is_none());
    unknown_action["effective"]["actionMap"]["futureAction"] = serde_json::json!({});
    assert_eq!(
        unknown_action["effective"]["actionMap"]["futureAction"],
        serde_json::json!({})
    );
    assert!(serde_json::from_value::<PermissionModeStatusV2>(unknown_action).is_err());

    let mut unknown_receipt_version =
        serde_json::to_value(PermissionModeCommandStatusV3::Committed {
            receipt: Box::new(PermissionModeChangeReceiptV3::V1 {
                receipt: v1_receipt(),
            }),
        })
        .expect("receipt union JSON value");
    let original_receipt_version = unknown_receipt_version.clone();
    unknown_receipt_version["receipt"]["version"] = serde_json::json!("v3");
    assert_ne!(unknown_receipt_version, original_receipt_version);
    assert!(
        serde_json::from_value::<PermissionModeCommandStatusV3>(unknown_receipt_version).is_err()
    );
}

#[test]
fn nested_nullable_history_fields_are_required() {
    let status = full_access_allow_status();
    let history = PermissionModeHistoryV2::capture(&status);
    let encoded = serde_json::to_value(history).expect("history JSON value");
    for field in ["containment", "expiresAtUnixMs"] {
        let mut value = encoded.clone();
        let removed = value.as_object_mut().expect("history object").remove(field);
        assert!(
            removed.is_some(),
            "required nullable history field missing: {field}"
        );
        let wire = serde_json::to_string(&value).expect("history JSON");
        assert!(serde_json::from_str::<PermissionModeHistoryV2>(&wire).is_err());
    }
}

#[test]
fn nested_nullable_history_fields_are_required_inside_v3_v2_receipts() {
    let encoded = serde_json::to_value(v2_committed_status()).expect("V3 V2 receipt JSON value");
    for field in ["containment", "expiresAtUnixMs"] {
        let mut missing = encoded.clone();
        let removed = missing["receipt"]["receipt"]["history"]
            .as_object_mut()
            .expect("V3 V2 receipt history object")
            .remove(field);
        assert!(
            removed.is_some(),
            "required nullable receipt history field missing: {field}"
        );
        let wire = serde_json::to_string(&missing).expect("V3 V2 missing field JSON");
        assert!(
            serde_json::from_str::<PermissionModeCommandStatusV3>(&wire).is_err(),
            "accepted missing V3 V2 receipt history field {field}"
        );
    }
}
