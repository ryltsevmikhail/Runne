use std::time::Duration;

use gocode_application::migration::{
    error::MigrationError,
    manifests::{ArtifactRef, DeprecationManifest, LegacyNewBindingPolicy},
    rollout::{CanaryPolicy, MAX_ROLLOUT_ADMISSION_LIMIT, PreDispatchFallbackPolicy, RolloutStep},
    rollout::{LegacyReferenceDisposition, LegacyReferenceInventory, LegacyReferenceSet},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        GatePolicyRef, MigrationCycleId, MigrationPlanId, RoutingGeneration, RoutingUnit,
    },
};
use gocode_domain::timestamp::Timestamp;

#[test]
fn canary_policy_requires_a_bounded_nonzero_admission_limit() {
    assert_eq!(
        CanaryPolicy::new(internal_cohort(), 0),
        Err(MigrationError::ProductionGatesUnavailable)
    );
    assert!(CanaryPolicy::new(internal_cohort(), 64).is_ok());
}

#[test]
fn canary_policy_is_exact_to_the_manifest_routing_unit() {
    let policy = CanaryPolicy::new(internal_cohort(), 64).unwrap();
    assert_eq!(
        policy.validate_routing_unit(&unrelated_unit()),
        Err(MigrationError::RoutingUnitMismatch)
    );
    assert_eq!(policy.validate_routing_unit(&internal_unit()), Ok(()));
}

#[test]
fn cohort_step_requires_a_complete_observation_window() {
    let result = RolloutStep::new(
        RoutingGeneration::new(2).unwrap(),
        internal_cohort(),
        2_048,
        Duration::from_secs(60),
        Timestamp::from_unix_micros(1_000_000),
        Timestamp::from_unix_micros(60_999_999),
        GatePolicyRef::new("policy-v1").unwrap(),
    );

    assert_eq!(result, Err(MigrationError::ObservationWindowIncomplete));
}

#[test]
fn cohort_step_requires_a_bounded_nonzero_admission_limit() {
    for invalid in [0, MAX_ROLLOUT_ADMISSION_LIMIT + 1] {
        assert_eq!(
            RolloutStep::new(
                RoutingGeneration::new(2).unwrap(),
                internal_cohort(),
                invalid,
                Duration::from_secs(60),
                Timestamp::from_unix_micros(1_000_000),
                Timestamp::from_unix_micros(61_000_000),
                GatePolicyRef::new("policy-v1").unwrap(),
            ),
            Err(MigrationError::ProductionGatesUnavailable)
        );
    }
}

#[test]
fn cohort_step_is_exact_to_generation_cohort_and_gate_policy() {
    let step = RolloutStep::new(
        RoutingGeneration::new(2).unwrap(),
        internal_cohort(),
        2_048,
        Duration::from_secs(60),
        Timestamp::from_unix_micros(1_000_000),
        Timestamp::from_unix_micros(61_000_000),
        GatePolicyRef::new("policy-v1").unwrap(),
    )
    .unwrap();

    assert_eq!(
        step.validate_for_prepare(
            &unrelated_unit(),
            RoutingGeneration::new(2).unwrap(),
            &GatePolicyRef::new("policy-v1").unwrap(),
            Timestamp::from_unix_micros(61_000_000),
        ),
        Err(MigrationError::RoutingUnitMismatch)
    );
    assert_eq!(
        step.validate_for_prepare(
            &internal_unit(),
            RoutingGeneration::new(3).unwrap(),
            &GatePolicyRef::new("policy-v1").unwrap(),
            Timestamp::from_unix_micros(61_000_000),
        ),
        Err(MigrationError::RoutingGenerationConflict {
            expected: RoutingGeneration::new(2).unwrap(),
            actual: RoutingGeneration::new(3).unwrap(),
        })
    );
    assert_eq!(
        step.validate_for_prepare(
            &internal_unit(),
            RoutingGeneration::new(2).unwrap(),
            &GatePolicyRef::new("policy-v2").unwrap(),
            Timestamp::from_unix_micros(61_000_000),
        ),
        Err(MigrationError::ProductionGatesUnavailable)
    );
}

#[test]
fn default_native_rejects_silent_profile_substitution() {
    let policy = PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
        source_profile: FeatureProfileRef::new(
            "different-profile",
            1,
            ArtifactDigest::from_bytes([9; 32]),
        )
        .unwrap(),
    };

    assert_eq!(
        policy.validate_routing_unit(&internal_unit()),
        Err(MigrationError::RoutingUnitMismatch)
    );
}

#[test]
fn default_native_accepts_only_the_exact_source_profile() {
    let policy = PreDispatchFallbackPolicy::ExplicitSourceBeforeAcceptance {
        source_profile: internal_unit().feature_profile,
    };

    assert_eq!(policy.validate_routing_unit(&internal_unit()), Ok(()));
}

#[test]
fn deprecation_inventory_requires_every_reference_disposition() {
    let mut inventory = clear_legacy_inventory();
    inventory.replay_and_client_cursors = LegacyReferenceSet {
        blocking_count: 1,
        identity_digest: ArtifactDigest::from_bytes([20; 32]),
        disposition: LegacyReferenceDisposition::Unresolved,
    };

    assert!(!inventory.is_retirement_clear());
    inventory.replay_and_client_cursors.blocking_count = 0;
    assert!(!inventory.is_retirement_clear());
    inventory.replay_and_client_cursors.disposition = LegacyReferenceDisposition::Resolved;
    assert!(inventory.is_retirement_clear());
}

#[test]
fn deprecation_manifest_publishes_closed_admission_and_exact_inventory() {
    let manifest = DeprecationManifest {
        manifest: artifact("deprecation", 30),
        plan_id: MigrationPlanId::new("plan-1").unwrap(),
        cycle_id: MigrationCycleId::new("cycle-1").unwrap(),
        cohort: internal_cohort(),
        replacement_profile: internal_unit().feature_profile,
        affected_identity_digest: ArtifactDigest::from_bytes([31; 32]),
        support_until: Timestamp::from_unix_micros(200),
        migration_guidance: artifact("migration-guidance", 32),
        drain_report: artifact("drain-report", 33),
        reference_inventory: clear_legacy_inventory(),
        new_binding_policy: LegacyNewBindingPolicy::Closed,
        created_at: Timestamp::from_unix_micros(100),
    };

    assert!(manifest.has_valid_identity());
}

fn clear_legacy_inventory() -> LegacyReferenceInventory {
    let cleared = |byte| LegacyReferenceSet {
        blocking_count: 0,
        identity_digest: ArtifactDigest::from_bytes([byte; 32]),
        disposition: LegacyReferenceDisposition::Resolved,
    };
    LegacyReferenceInventory {
        active_and_in_flight: cleared(20),
        recovery_candidates: cleared(21),
        uncertain_effects: cleared(22),
        timers_processes_cleanup: cleared(23),
        replay_and_client_cursors: cleared(24),
        audit_and_retention: cleared(25),
        rollback_artifacts: cleared(26),
        credentials_packages_processes: cleared(27),
    }
}

fn internal_unit() -> RoutingUnit {
    routing_unit("internal")
}

fn unrelated_unit() -> RoutingUnit {
    routing_unit("external")
}

fn routing_unit(client_class: &str) -> RoutingUnit {
    RoutingUnit {
        deployment: DeploymentId::new("production").unwrap(),
        cohort: CohortSelector::new(vec![
            CohortDimension::new("client_class", client_class).unwrap(),
        ])
        .unwrap(),
        feature_profile: FeatureProfileRef::new("taskrun", 1, ArtifactDigest::from_bytes([1; 32]))
            .unwrap(),
        contract_digest: ArtifactDigest::from_bytes([2; 32]),
        schema_digest: ArtifactDigest::from_bytes([3; 32]),
        config_digest: ArtifactDigest::from_bytes([4; 32]),
    }
}

fn internal_cohort() -> CohortSelector {
    internal_unit().cohort
}

fn artifact(name: &str, byte: u8) -> ArtifactRef {
    ArtifactRef::new(
        format!("artifact://{name}"),
        ArtifactDigest::from_bytes([byte; 32]),
    )
    .unwrap()
}
