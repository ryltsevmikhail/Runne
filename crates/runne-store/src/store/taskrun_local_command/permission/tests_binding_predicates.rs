//! Logical operand sensitivity using one genuine prepared target and owned temporary databases.
use super::super::{capture_checks, model};
use super::{ceremony, fixture::Fixture, target};
use runne_application::permission_modes::{
    LocalCommandPermissionBindingInputV1, LocalCommandPermissionBindingV1, PermissionMode,
};
use runne_domain::id::IntegrityDigest;
use runne_platform::local_command_linux::PermissionTargetObservationV1;

fn input(b: &LocalCommandPermissionBindingV1) -> LocalCommandPermissionBindingInputV1 {
    LocalCommandPermissionBindingInputV1 {
        selection: b.selection().clone(),
        assignment: b.assignment().clone(),
        claim_stream_version: b.claim_stream_version(),
        invocation_id: b.invocation_id(),
        project_id: b.project_id(),
        project_version: b.project_version(),
        workspace_version: b.workspace_version(),
        admitted_root_version: b.admitted_root_version(),
        held_root_identity_digest: b.held_root_identity_digest(),
        command: b.command().clone(),
        command_intent_digest: b.command_intent_digest(),
        approval: b.approval().clone(),
        scope: b.scope().clone(),
        closed_rules_snapshot: b.closed_rules_snapshot(),
        closed_rules_digest: b.closed_rules_digest(),
        limits: b.limits(),
    }
}

fn flipped(digest: IntegrityDigest) -> IntegrityDigest {
    let mut bytes = *digest.as_bytes();
    bytes[0] ^= 1;
    IntegrityDigest::from_bytes(bytes)
}

// Same order as both production comparators; inspect every operand independently.
fn equal_operands(
    binding: &LocalCommandPermissionBindingV1,
    observed: PermissionTargetObservationV1,
) -> [bool; 7] {
    let a = binding.approval();
    [
        a.normalized_arguments_digest.as_bytes() == observed.normalized_arguments_digest(),
        a.tool_schema_digest.as_bytes() == observed.schema_digest(),
        a.target_identity_digest.as_bytes() == observed.target_identity(),
        a.target_version == observed.target_version(),
        a.environment_digest.as_bytes() == observed.environment_digest(),
        a.cwd_identity_digest.as_bytes() == observed.cwd_identity(),
        a.executable_digest.map(|value| *value.as_bytes()) == Some(*observed.executable_digest()),
    ]
}

#[test]
fn seven_isolated_expected_approval_operands_refuse_same_prepared_observation() {
    // Existing fixture/ceremony supply test-only authority context.
    // Preparation owns temp files/DBs and sealed bytes; this is not pure in-memory data.
    let f = Fixture::new();
    ceremony::commit(&f, PermissionMode::RiskBased, 0);
    let (original, prepared) = target::prepare(&f);
    let saved_binding = original.clone();
    let observed = prepared.observation();
    let saved_observation = observed;
    assert_eq!(equal_operands(&original, observed), [true; 7]);
    assert!(capture_checks::target_matches(&original, observed));
    assert!(model::observation_matches(&original, observed));

    let names = [
        "normalized arguments",
        "schema",
        "target identity",
        "target version",
        "environment",
        "cwd",
        "executable",
    ];
    for (dimension, name) in names.into_iter().enumerate() {
        let mut value = input(&original);
        let a = &mut value.approval;
        match dimension {
            0 => a.normalized_arguments_digest = flipped(a.normalized_arguments_digest),
            1 => a.tool_schema_digest = flipped(a.tool_schema_digest),
            2 => a.target_identity_digest = flipped(a.target_identity_digest),
            3 => {
                a.target_version = a
                    .target_version
                    .checked_add(1)
                    .expect("prepared target version must allow a nonoverflowing increment");
                assert!(a.target_version > 0);
            }
            4 => a.environment_digest = flipped(a.environment_digest),
            5 => a.cwd_identity_digest = flipped(a.cwd_identity_digest),
            6 => a.executable_digest = Some(flipped(a.executable_digest.unwrap())),
            _ => unreachable!(),
        }
        let different = LocalCommandPermissionBindingV1::checked(value)
            .unwrap_or_else(|error| panic!("{name}: checked expected data required: {error:?}"));
        let equal = equal_operands(&different, observed);
        assert_eq!(equal.iter().filter(|&&same| same).count(), 6, "{name}");
        assert_eq!(equal.iter().filter(|&&same| !same).count(), 1, "{name}");
        for (index, same) in equal.into_iter().enumerate() {
            assert_eq!(same, index != dimension, "{name}: operand {index}");
        }
        assert!(
            !capture_checks::target_matches(&different, observed),
            "{name}"
        );
        assert!(!model::observation_matches(&different, observed), "{name}");
        assert_eq!(
            original, saved_binding,
            "{name}: original binding unchanged"
        );
        assert_eq!(observed, saved_observation, "{name}: observation unchanged");
        assert_eq!(
            prepared.observation(),
            saved_observation,
            "{name}: prepared unchanged"
        );
    }

    assert_eq!(original, saved_binding);
    assert_eq!(observed, saved_observation);
    assert_eq!(prepared.observation(), saved_observation);
    assert_eq!(equal_operands(&original, observed), [true; 7]);
    assert!(capture_checks::target_matches(&original, observed));
    assert!(model::observation_matches(&original, observed));
}
