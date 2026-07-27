use std::time::Duration;

use gocode_application::migration::{
    error::MigrationError,
    rollout::{CanaryPolicy, MAX_ROLLOUT_ADMISSION_LIMIT, RolloutStep},
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        GatePolicyRef, RoutingGeneration, RoutingUnit,
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
