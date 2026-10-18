use super::support::*;
use runne_domain::id::IntegrityDigest;

const LEGACY_V1_READY_STATUS_GOLDEN: &[u8] = br#"{"selectedMode":"full_access","effective":{"state":"ready","mode":"full_access","preset_version":1,"scope_digest":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"containment":"same_user_composite_v1"},"authorizationRevision":8,"presetVersion":1,"managedPolicyVersion":3,"pendingApprovalIds":[],"containment":"same_user_composite_v1","networkState":"broad_same_user","expiresAtUnixMs":1700000000000}"#;
const LEGACY_V1_READY_HISTORY_GOLDEN: &[u8] = br#"{"selectedMode":"full_access","effective":{"state":"ready","mode":"full_access","preset_version":1,"scope_digest":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"containment":"same_user_composite_v1"},"authorizationRevision":8,"presetVersion":1,"managedPolicyVersion":3,"containment":"same_user_composite_v1","networkState":"broad_same_user","expiresAtUnixMs":1700000000000}"#;
const LEGACY_V1_READY_RECEIPT_GOLDEN: &[u8] = br#"{"commandId":[0,0,0,0,0,0,112,0,128,0,0,0,0,0,0,1],"idempotencyKey":"mode-change-1","intentDigest":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"authorizationRevision":8,"selectedMode":"full_access","history":{"selectedMode":"full_access","effective":{"state":"ready","mode":"full_access","preset_version":1,"scope_digest":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"containment":"same_user_composite_v1"},"authorizationRevision":8,"presetVersion":1,"managedPolicyVersion":3,"containment":"same_user_composite_v1","networkState":"broad_same_user","expiresAtUnixMs":1700000000000}}"#;
const LEGACY_V1_READY_V3_GOLDEN: &[u8] = br#"{"state":"committed","receipt":{"version":"v1","receipt":{"commandId":[0,0,0,0,0,0,112,0,128,0,0,0,0,0,0,1],"idempotencyKey":"mode-change-1","intentDigest":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"authorizationRevision":8,"selectedMode":"full_access","history":{"selectedMode":"full_access","effective":{"state":"ready","mode":"full_access","preset_version":1,"scope_digest":[9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9,9],"containment":"same_user_composite_v1"},"authorizationRevision":8,"presetVersion":1,"managedPolicyVersion":3,"containment":"same_user_composite_v1","networkState":"broad_same_user","expiresAtUnixMs":1700000000000}}}}"#;

fn legacy_v1_ready_effective() -> PermissionEffectiveStateV1 {
    PermissionEffectiveStateV1::Ready {
        mode: PermissionModeV1::FullAccess,
        preset_version: PermissionPresetVersionV1::V1,
        scope_digest: IntegrityDigest::from_bytes([9; 32]),
        containment: PermissionContainmentV1::SameUserCompositeV1,
    }
}

fn legacy_v1_ready_status() -> PermissionModeStatusV1 {
    PermissionModeStatusV1 {
        selected_mode: PermissionModeV1::FullAccess,
        effective: legacy_v1_ready_effective(),
        authorization_revision: 8,
        preset_version: PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        pending_approval_ids: Vec::new(),
        containment: Some(PermissionContainmentV1::SameUserCompositeV1),
        network_state: PermissionNetworkStateV1::BroadSameUser,
        expires_at_unix_ms: Some(1_700_000_000_000),
    }
}

fn legacy_v1_ready_history() -> PermissionModeHistoryV1 {
    PermissionModeHistoryV1 {
        selected_mode: PermissionModeV1::FullAccess,
        effective: legacy_v1_ready_effective(),
        authorization_revision: 8,
        preset_version: PermissionPresetVersionV1::V1,
        managed_policy_version: 3,
        containment: Some(PermissionContainmentV1::SameUserCompositeV1),
        network_state: PermissionNetworkStateV1::BroadSameUser,
        expires_at_unix_ms: Some(1_700_000_000_000),
    }
}

fn legacy_v1_ready_receipt() -> PermissionModeChangeReceiptV1 {
    PermissionModeChangeReceiptV1 {
        command_id: command_id(),
        idempotency_key: "mode-change-1".to_owned(),
        intent_digest: IntegrityDigest::from_bytes([2; 32]),
        authorization_revision: 8,
        selected_mode: PermissionModeV1::FullAccess,
        history: legacy_v1_ready_history(),
    }
}

#[test]
fn frozen_v1_status_and_receipt_json_bytes_remain_unchanged() {
    let status_golden = br#"{"selectedMode":"risk_based","effective":{"state":"notReady","reason":"preset_unavailable"},"authorizationRevision":8,"presetVersion":1,"managedPolicyVersion":3,"pendingApprovalIds":[[0,0,0,0,0,0,112,0,128,0,0,0,0,0,0,1]],"containment":null,"networkState":"unavailable","expiresAtUnixMs":null}"#;
    let receipt_golden = br#"{"commandId":[0,0,0,0,0,0,112,0,128,0,0,0,0,0,0,1],"idempotencyKey":"mode-change-1","intentDigest":[2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2],"authorizationRevision":8,"selectedMode":"risk_based","history":{"selectedMode":"risk_based","effective":{"state":"notReady","reason":"preset_unavailable"},"authorizationRevision":8,"presetVersion":1,"managedPolicyVersion":3,"containment":null,"networkState":"unavailable","expiresAtUnixMs":null}}"#;

    assert_eq!(
        serde_json::to_vec(&v1_status())
            .expect("V1 status JSON")
            .as_slice(),
        status_golden
    );
    assert_eq!(
        serde_json::to_vec(&v1_receipt())
            .expect("V1 receipt JSON")
            .as_slice(),
        receipt_golden
    );
}

#[test]
fn legacy_v1_ready_bytes_remain_frozen_through_history_receipt_and_v3() {
    let status = legacy_v1_ready_status();
    let history = legacy_v1_ready_history();
    let receipt = legacy_v1_ready_receipt();
    let v3 = PermissionModeCommandStatusV3::Committed {
        receipt: Box::new(PermissionModeChangeReceiptV3::V1 {
            receipt: receipt.clone(),
        }),
    };

    assert_eq!(
        serde_json::to_vec(&status).expect("legacy ready V1 status JSON"),
        LEGACY_V1_READY_STATUS_GOLDEN
    );
    assert_eq!(
        serde_json::to_vec(&history).expect("legacy ready V1 history JSON"),
        LEGACY_V1_READY_HISTORY_GOLDEN
    );
    assert_eq!(
        serde_json::to_vec(&receipt).expect("legacy ready V1 receipt JSON"),
        LEGACY_V1_READY_RECEIPT_GOLDEN
    );
    assert_eq!(
        serde_json::to_vec(&v3).expect("legacy ready V3 wrapper JSON"),
        LEGACY_V1_READY_V3_GOLDEN
    );
    assert_eq!(
        serde_json::from_slice::<PermissionModeCommandStatusV3>(LEGACY_V1_READY_V3_GOLDEN)
            .expect("legacy ready V3 wrapper decode"),
        v3
    );
}

#[test]
fn v3_receipt_union_roundtrips_both_frozen_v1_and_new_v2_receipts() {
    let pending = PermissionModeCommandStatusV3::PendingNativeConfirmation {
        command_id: command_id(),
        expires_at_unix_ms: 1_700_000_000_000,
    };
    assert_eq!(
        serde_json::to_value(&pending).expect("V3 status JSON"),
        serde_json::json!({
            "state": "pendingNativeConfirmation",
            "commandId": ID_BYTES,
            "expiresAtUnixMs": 1_700_000_000_000_i64,
        })
    );

    let v1 = PermissionModeCommandStatusV3::Committed {
        receipt: Box::new(PermissionModeChangeReceiptV3::V1 {
            receipt: v1_receipt(),
        }),
    };
    let v1_wire = serde_json::to_value(&v1).expect("V1 union JSON");
    assert_eq!(v1_wire["receipt"]["version"], serde_json::json!("v1"));
    assert_eq!(
        v1_wire["receipt"]["receipt"],
        serde_json::to_value(v1_receipt()).expect("frozen V1 receipt")
    );
    assert_eq!(
        serde_json::from_value::<PermissionModeCommandStatusV3>(v1_wire.clone())
            .expect("V1 receipt union roundtrip"),
        v1
    );
    assert_eq!(v1.validate(), Ok(()));

    let status = full_access_allow_status();
    let history = PermissionModeHistoryV2::capture(&status);
    let v2_receipt = v2_receipt(history);
    let v2 = PermissionModeCommandStatusV3::Committed {
        receipt: Box::new(PermissionModeChangeReceiptV3::V2 {
            receipt: v2_receipt.clone(),
        }),
    };
    let v2_wire = serde_json::to_value(&v2).expect("V2 union JSON");
    assert_eq!(v2_wire["receipt"]["version"], serde_json::json!("v2"));
    assert_eq!(
        v2_wire["receipt"]["receipt"],
        serde_json::to_value(&v2_receipt).expect("V2 receipt")
    );
    let encoded = serde_json::to_string(&v2).expect("V2 union bytes");
    assert_eq!(
        serde_json::from_str::<PermissionModeCommandStatusV3>(&encoded)
            .expect("V2 receipt union roundtrip"),
        v2
    );
    assert_eq!(v2.validate(), Ok(()));

    let mut invalid_nested_receipt = v2_receipt;
    invalid_nested_receipt.history.observation_generation = 0;
    let invalid_v2 = PermissionModeCommandStatusV3::Committed {
        receipt: Box::new(PermissionModeChangeReceiptV3::V2 {
            receipt: invalid_nested_receipt,
        }),
    };
    assert_eq!(
        invalid_v2.validate(),
        Err(PermissionModeValidationErrorV2::ZeroObservationGeneration)
    );
}
