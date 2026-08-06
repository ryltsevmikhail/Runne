use gocode_api::{
    ExpiryAggregateV1, MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1,
    OPERATIONAL_TELEMETRY_CAPABILITY_V1, OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1,
    RecoveryObservationStatusV1, RuntimeBudgetV1, RuntimeDurableAccountingV1,
    RuntimeDurableOperationalTelemetryV1, RuntimeOperationalTelemetrySnapshotV1,
    RuntimeRecoveryTransientV1, TelemetryCompletenessV1, TelemetryFreshnessV1,
    TelemetrySectionMetaV1,
};

#[path = "operational_telemetry_contract/aliases.rs"]
mod aliases;
#[path = "operational_telemetry_contract/closure.rs"]
mod closure;
#[path = "operational_telemetry_contract/security.rs"]
mod security;

const VALID_SNAPSHOT: &[u8] = br#"{
  "schemaVersion":1,"observedAtUnixSeconds":10,"launchGeneration":1,
  "durable":{"meta":{"observedAtUnixSeconds":10,"freshness":"observed_in_current_cycle","completeness":"complete"},"accounting":{"tokens":{"limit":10,"reserved":2,"settled":3,"remaining":5},"costMicroUsd":{"limit":10,"reserved":2,"settled":3,"remaining":5}},"providerEffectAuthorities":{"activeCount":1,"expiredActiveCount":0,"nearestUnexpiredExpiryUnixSeconds":11},"providerApprovalLease":{"activeCount":0,"expiredActiveCount":0,"nearestUnexpiredExpiryUnixSeconds":null},"committedProviderEffects":{"activeCount":0,"expiredActiveCount":0,"nearestUnexpiredExpiryUnixSeconds":null},"uncertainAttempts":0},
  "recoveryTransient":{"meta":{"observedAtUnixSeconds":10,"freshness":"observed_in_current_cycle","completeness":"complete"},"status":"lower_bound_since_launch","observedOutboxRecoveriesInGeneration":0,"droppedEventCount":0,"counterSaturated":false}
}"#;

fn with_replaced(needle: &str, replacement: &str) -> Vec<u8> {
    std::str::from_utf8(VALID_SNAPSHOT)
        .expect("fixture is UTF-8")
        .replace(needle, replacement)
        .into_bytes()
}

#[test]
fn snapshot_rejects_unknown_fields_and_invalid_budget() {
    let bad = br#"{"schemaVersion":1,"observedAtUnixSeconds":1,"launchGeneration":1,"extra":0}"#;
    assert!(serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(bad).is_err());
    assert!(RuntimeBudgetV1::new(10, 6, 5).is_err());
    assert_eq!(
        OPERATIONAL_TELEMETRY_CAPABILITY_V1,
        "runtime.operational-telemetry.v1"
    );
    assert_eq!(OPERATIONAL_TELEMETRY_SCHEMA_VERSION_V1, 1);
    assert_eq!(MAX_OPERATIONAL_TELEMETRY_WIRE_BYTES_V1, 65_536);
}

#[test]
fn snapshot_rejects_unknown_enums_zero_generation_and_invalid_aggregates() {
    assert!(
        serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(VALID_SNAPSHOT).is_ok()
    );
    assert!(
        serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(&with_replaced(
            "\"launchGeneration\":1",
            "\"launchGeneration\":0"
        ))
        .is_err()
    );
    assert!(
        serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(&with_replaced(
            "\"schemaVersion\":1",
            "\"schemaVersion\":2"
        ))
        .is_err()
    );
    assert!(
        serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(&with_replaced(
            "\"complete\"",
            "\"unknown\""
        ))
        .is_err()
    );
    assert!(ExpiryAggregateV1::new(1, 2, None, 10).is_err());
    assert!(ExpiryAggregateV1::new(1, 0, Some(10), 10).is_err());
    assert!(serde_json::from_slice::<ExpiryAggregateV1>(
        br#"{"activeCount":0,"expiredActiveCount":0,"nearestUnexpiredExpiryUnixSeconds":null,"extra":0}"#
    )
    .is_err());
}

#[test]
fn section_and_recovery_invariants_are_closed() {
    assert!(
        TelemetrySectionMetaV1::new(
            1,
            TelemetryFreshnessV1::Unavailable,
            TelemetryCompletenessV1::Complete,
        )
        .is_err()
    );
    assert!(
        TelemetrySectionMetaV1::new(
            1,
            TelemetryFreshnessV1::ObservedInCurrentCycle,
            TelemetryCompletenessV1::Unavailable,
        )
        .is_err()
    );
    assert!(matches!(
        RecoveryObservationStatusV1::LowerBoundSinceLaunch,
        RecoveryObservationStatusV1::LowerBoundSinceLaunch
    ));
    assert!(
        serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(&with_replaced(
            "\"droppedEventCount\":0",
            "\"droppedEventCount\":1"
        ))
        .is_err()
    );
    assert!(
        serde_json::from_slice::<RuntimeOperationalTelemetrySnapshotV1>(&with_replaced(
            "\"counterSaturated\":false",
            "\"counterSaturated\":true"
        ))
        .is_err()
    );
}

#[test]
fn durable_completeness_and_each_recovery_status_are_validated() {
    let complete = TelemetrySectionMetaV1::new(
        10,
        TelemetryFreshnessV1::ObservedInCurrentCycle,
        TelemetryCompletenessV1::Complete,
    )
    .unwrap();
    let partial = TelemetrySectionMetaV1::new(
        10,
        TelemetryFreshnessV1::ObservedInCurrentCycle,
        TelemetryCompletenessV1::Partial,
    )
    .unwrap();
    let unavailable = TelemetrySectionMetaV1::new(
        10,
        TelemetryFreshnessV1::Unavailable,
        TelemetryCompletenessV1::Unavailable,
    )
    .unwrap();
    let accounting = RuntimeDurableAccountingV1::new(
        RuntimeBudgetV1::new(1, 0, 0).unwrap(),
        RuntimeBudgetV1::new(1, 0, 0).unwrap(),
    );

    assert!(
        RuntimeDurableOperationalTelemetryV1::new(complete.clone(), None, None, None, None, None,)
            .is_err()
    );
    assert!(
        RuntimeDurableOperationalTelemetryV1::new(
            unavailable.clone(),
            Some(accounting),
            None,
            None,
            None,
            None,
        )
        .is_err()
    );
    assert!(
        RuntimeRecoveryTransientV1::new(
            complete.clone(),
            RecoveryObservationStatusV1::LowerBoundSinceLaunch,
            None,
            0,
            false,
        )
        .is_err()
    );
    assert!(
        RuntimeRecoveryTransientV1::new(
            partial.clone(),
            RecoveryObservationStatusV1::TruncatedLowerBoundSinceLaunch,
            Some(1),
            0,
            false,
        )
        .is_err()
    );
    assert!(
        RuntimeRecoveryTransientV1::new(
            unavailable,
            RecoveryObservationStatusV1::Unavailable,
            Some(1),
            0,
            false,
        )
        .is_err()
    );
    assert!(
        RuntimeRecoveryTransientV1::new(
            partial,
            RecoveryObservationStatusV1::TruncatedLowerBoundSinceLaunch,
            Some(1),
            1,
            true,
        )
        .is_err()
    );
}
