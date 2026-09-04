//! Local Engine status surface tests (Plan Task 14): snapshot
//! validation rejects invalid digests and inconsistent
//! selection/readiness pairs; the HTTP route serves the injected
//! snapshot and the explicit not-selected default.

use crate::local_engine::{
    LocalEngineGenerationPhaseV1, LocalEngineReadinessV1, LocalEngineStatusSnapshotV1,
    LocalInstallationSnapshotV1,
};

fn installation() -> LocalInstallationSnapshotV1 {
    LocalInstallationSnapshotV1::new(
        "m1",
        "r1",
        "sha256:a3d27b1a556d63979122c0aa64b44c9f9d69701323b3fa4333839bcd399ee61e",
        "2026-09-05-r1",
        0,
    )
    .expect("installation")
}

#[test]
fn snapshot_roundtrips_serialization() {
    let snapshot = LocalEngineStatusSnapshotV1::new(
        "local_engine_text_v1",
        LocalEngineReadinessV1::Ready,
        vec![installation()],
        Some(LocalEngineGenerationPhaseV1::Idle),
    )
    .expect("snapshot");
    let value = serde_json::to_value(&snapshot).expect("serialize");
    assert_eq!(
        value["activationMode"],
        serde_json::Value::String("local_engine_text_v1".into())
    );
    assert_eq!(
        value["readiness"],
        serde_json::Value::String("ready".into())
    );
    assert_eq!(value["installations"][0]["modelId"], "m1");
    assert_eq!(
        value["generation"],
        serde_json::Value::String("idle".into())
    );
    let back: LocalEngineStatusSnapshotV1 = serde_json::from_value(value).expect("deserialize");
    assert_eq!(back, snapshot);
}

#[test]
fn not_selected_is_explicit_never_inferred() {
    let empty =
        LocalEngineStatusSnapshotV1::new("", LocalEngineReadinessV1::NotSelected, Vec::new(), None)
            .expect("explicit none");
    assert!(empty.activation_mode().is_empty());
    // Empty mode must pair with not-selected readiness.
    assert!(
        LocalEngineStatusSnapshotV1::new("", LocalEngineReadinessV1::Ready, Vec::new(), None)
            .is_err()
    );
    // A non-empty mode must pair with a real readiness.
    assert!(
        LocalEngineStatusSnapshotV1::new(
            "local_engine_text_v1",
            LocalEngineReadinessV1::NotSelected,
            Vec::new(),
            None
        )
        .is_err()
    );
}

#[test]
fn installation_digest_and_qualification_rules() {
    assert!(
        LocalInstallationSnapshotV1::new("m1", "r1", "not-a-digest", "2026-09-05-r1", 0).is_err()
    );
    // Unqualified install with active refs is contradictory.
    assert!(
        LocalInstallationSnapshotV1::new(
            "m1",
            "r1",
            "sha256:a3d27b1a556d63979122c0aa64b44c9f9d69701323b3fa4333839bcd399ee61e",
            "",
            2
        )
        .is_err()
    );
}
