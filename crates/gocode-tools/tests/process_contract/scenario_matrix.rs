struct ScenarioProof {
    source_path: &'static str,
    test_name: &'static str,
}

struct ScenarioMapping {
    id: &'static str,
    proofs: &'static [ScenarioProof],
}

macro_rules! scenario {
    ($id:literal, $path:literal, $name:literal $(; $more_path:literal, $more_name:literal)*) => {
        ScenarioMapping {
            id: $id,
            proofs: &[
                ScenarioProof { source_path: $path, test_name: $name },
                $(ScenarioProof { source_path: $more_path, test_name: $more_name }),*
            ],
        }
    };
}

const SCENARIO_MATRIX: [ScenarioMapping; 30] = [
    scenario!("SC-PROC-01", "crates/gocode-security/src/process_contract/tests/authorization/basic.rs", "exact_valid_authorization_is_recorded_once"),
    scenario!("SC-PROC-02", "crates/gocode-security/src/process_contract/tests/authorization/basic.rs", "capability_and_approval_are_required_and_expire_at_their_deadline"),
    scenario!("SC-PROC-03", "crates/gocode-tools/src/process_contract/claim_unit_tests.rs", "first_projection_replays_once_and_changed_binding_or_digest_conflicts"),
    scenario!("SC-PROC-04",
        "crates/gocode-security/src/process_contract/tests/current_context.rs", "principal_mismatch_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context.rs", "authority_mismatch_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context.rs", "owner_mismatch_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context.rs", "attempt_mismatch_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context.rs", "session_mismatch_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context.rs", "generation_mismatch_is_denied"),
    scenario!("SC-PROC-05", "crates/gocode-security/src/process_contract/tests/approval.rs", "approval_digest_mismatch_is_denied"),
    scenario!("SC-PROC-06",
        "crates/gocode-security/src/process_contract/tests/current_context/verification.rs", "executable_held_token_substitution_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context/verification.rs", "executable_content_substitution_is_denied";
        "crates/gocode-security/src/process_contract/tests/current_context/verification.rs", "executable_filesystem_substitution_is_denied"),
    scenario!("SC-PROC-07", "crates/gocode-tools/src/process_contract/orchestrator_tests.rs", "executable_substitution_after_verification_vetoes_launch_and_replays_uncertain"),
    scenario!("SC-PROC-08", "crates/gocode-security/src/process_contract/tests/current_context/verification.rs", "cwd_allowed_root_substitution_is_denied"),
    scenario!("SC-PROC-09", "crates/platform-ports/src/process/tests.rs", "constructors_reject_symlink_proof_failure"),
    scenario!("SC-PROC-10", "crates/gocode-security/src/process_contract/tests/input.rs", "argv_enforces_count_element_and_total_bounds"),
    scenario!("SC-PROC-11", "crates/gocode-security/src/process_contract/tests/input.rs", "portable_utf8_rejects_invalid_utf8_and_nul"),
    scenario!("SC-PROC-12", "crates/gocode-security/src/process_contract/tests/input.rs", "shell_like_argv_is_preserved_as_literal_portable_utf8"),
    scenario!("SC-PROC-13", "crates/gocode-security/tests/process_contract/authorization.rs", "environment_is_empty_by_default_without_ambient_lookup"),
    scenario!("SC-PROC-14", "crates/gocode-security/src/process_contract/tests/environment.rs", "exact_grant_still_rejects_execution_shaping_environment_names"),
    scenario!("SC-PROC-15", "crates/gocode-tools/tests/process_contract/output.rs", "stdio_bounds_allow_closed_stdin_and_reject_nonempty_input"),
    scenario!("SC-PROC-16", "crates/gocode-tools/src/process_contract/output/tests/truncation.rs", "cap_calls_stop_capture_and_records_prefix_metadata"),
    scenario!("SC-PROC-17", "crates/gocode-tools/src/process_contract/f1_tests.rs", "deadline_cancellation_and_regression_have_distinct_timing_dispositions"),
    scenario!("SC-PROC-18",
        "crates/gocode-tools/src/process_contract/orchestrator_lifecycle_tests.rs", "cancellation_before_dispatch_is_denied_without_claim_or_platform_call";
        "crates/gocode-tools/src/process_contract/orchestrator_lifecycle_tests.rs", "cancellation_during_running_uses_exact_forced_cleanup_sequence"),
    scenario!("SC-PROC-19",
        "crates/gocode-tools/src/process_contract/orchestrator_supervision_tests.rs", "graceful_failure_still_attempts_forced_exact_tree_cleanup";
        "crates/gocode-tools/src/process_contract/orchestrator_termination_tests.rs", "wait_for_grace_unavailable_attempts_forced_cleanup_without_relaunch"),
    scenario!("SC-PROC-20", "crates/gocode-tools/src/process_contract/f1_tests.rs", "owner_mismatch_and_unverified_descendants_settle_uncertain"),
    scenario!("SC-PROC-21", "crates/gocode-tools/src/process_contract/orchestrator_supervision_tests.rs", "owner_or_cleanup_mismatch_completion_becomes_uncertain"),
    scenario!("SC-PROC-22", "crates/gocode-tools/src/process_contract/orchestrator_tests.rs", "cancellation_uses_exact_tree_control_then_forced_virtual_cleanup"),
    scenario!("SC-PROC-23", "crates/gocode-tools/src/process_contract/lifecycle_unit_tests.rs", "lifecycle_accepts_only_the_closed_transition_graph"),
    scenario!("SC-PROC-24", "crates/gocode-tools/src/process_contract/orchestrator_failure_tests.rs", "launch_and_forced_ambiguities_are_uncertain_while_graceful_cleanup_is_terminal"),
    scenario!("SC-PROC-25", "crates/gocode-tools/src/process_contract/recovery_tests.rs", "recovery_cas_conflict_does_not_redispatch_or_retry"),
    scenario!("SC-PROC-26", "crates/gocode-tools/src/process_contract/orchestrator_supervision_completion_tests.rs", "normal_completion_observation_atomically_settles_output_and_replays_without_calls"),
    scenario!("SC-PROC-27", "crates/gocode-tools/src/process_contract/output/tests.rs", "raw_payload_requires_exact_caller_and_debug_is_redacted"),
    scenario!("SC-PROC-28",
        "crates/gocode-security/src/process_contract/tests/environment.rs", "exact_grant_rejects_all_dynamic_loader_environment_names";
        "crates/gocode-tools/src/process_contract/orchestrator_marker_tests.rs", "marker_output_persists_only_evidence_and_replay_has_no_source_or_effect_calls"),
    scenario!("SC-PROC-29", "crates/gocode-platform/tests/process_contract_stubs.rs", "all_platform_stubs_fail_closed"),
    scenario!("SC-PROC-30", "crates/gocode-tools/tests/process_contract/source_scan.rs", "process_contract_production_paths_have_no_ambient_or_process_apis"),
];

#[test]
fn scenario_matrix_is_ordered_complete_and_points_to_real_behavior_tests() {
    let expected = (1..=30)
        .map(|number| format!("SC-PROC-{number:02}"))
        .collect::<Vec<_>>();
    let actual = SCENARIO_MATRIX
        .iter()
        .map(|mapping| mapping.id.to_owned())
        .collect::<Vec<_>>();
    assert_eq!(actual, expected, "scenario IDs must be ordered, unique, and complete");

    for mapping in SCENARIO_MATRIX {
        assert!(!mapping.proofs.is_empty(), "{}: no proofs", mapping.id);
        for proof in mapping.proofs {
            let source = source_manifest::TASK6_TEST_FIXTURE_SOURCES
                .iter()
                .find_map(|(path, source)| (*path == proof.source_path).then_some(*source))
                .unwrap_or_else(|| panic!("{}: source missing: {}", mapping.id, proof.source_path));
            assert!(
                has_exact_test_declaration(source, proof.test_name),
                "{}: missing exact #[test] fn {} in {}",
                mapping.id,
                proof.test_name,
                proof.source_path
            );
            assert!(
                !matches!(proof.test_name, "placeholder" | "todo" | "type_name_only"),
                "{}: placeholder mapping",
                mapping.id
            );
        }
    }
}

fn has_exact_test_declaration(source: &str, name: &str) -> bool {
    let lines = source.lines().collect::<Vec<_>>();
    lines.iter().enumerate().any(|(index, line)| {
        line.trim_start()
            .strip_prefix("fn ")
            .and_then(|declaration| declaration.strip_prefix(name))
            .is_some_and(|suffix| {
                matches!(suffix.trim_start().chars().next(), Some('(' | '<'))
                    && lines[..index]
                        .iter()
                        .rev()
                        .find(|line| !line.trim().is_empty())
                        .is_some_and(|line| line.trim() == "#[test]")
            })
    }) || has_macro_generated_test(source, name)
}

fn has_macro_generated_test(source: &str, name: &str) -> bool {
    source.contains("#[test]\n        fn $name()")
        && source
            .lines()
            .any(|line| matches!(line.trim(), "identity_mismatch!(" | "verification_mismatch!("))
        && source
            .lines()
            .any(|line| line.trim().strip_suffix(',') == Some(name))
}
