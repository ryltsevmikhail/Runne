use gocode_application::migration::{
    error::MigrationError,
    rollout::CanaryPolicy,
    types::{
        ArtifactDigest, CohortDimension, CohortSelector, DeploymentId, FeatureProfileRef,
        RoutingUnit,
    },
};

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
