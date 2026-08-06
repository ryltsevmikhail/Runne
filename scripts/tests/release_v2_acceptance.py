"""Machine-readable Task 12 acceptance-to-test registry."""

import ast
import inspect
import textwrap
from importlib import import_module


ACCEPTANCE_REGISTRY = {
    1: ("test_release_v2_identity.IdentityTests.test_at_01_valid_structural_candidate", "test_release_v2_identity.IdentityTests.test_at_01_rejects_noncanonical_identity"),
    2: ("test_release_v2_identity.IdentityTests.test_at_02_clean_candidate_is_accepted", "test_release_v2_identity.IdentityTests.test_at_02_dirty_candidate_blocks"),
    3: ("test_release_v2_identity.IdentityTests.test_at_03_exact_source_revision_is_accepted", "test_release_v2_identity.IdentityTests.test_at_03_wrong_source_revision_blocks"),
    4: ("test_release_v2_identity.IdentityTests.test_at_04_exact_lock_digests_are_accepted", "test_release_v2_identity.IdentityTests.test_at_04_wrong_lock_digest_blocks"),
    5: ("test_release_v2_identity.IdentityTests.test_at_05_bound_candidate_is_accepted", "test_release_v2_identity.IdentityTests.test_at_05_candidate_mismatch_blocks"),
    6: ("test_release_v2_identity.IdentityTests.test_at_06_known_manifest_is_accepted", "test_release_v2_identity.IdentityTests.test_at_06_unknown_manifest_blocks"),
    7: ("test_release_v2_inventory.InventoryTests.test_at_07_complete_components_are_accepted", "test_release_v2_inventory.InventoryTests.test_at_07_missing_extra_duplicate_component_blocks"),
    8: ("test_release_v2_inventory.InventoryTests.test_at_08_relative_regular_path_is_accepted", "test_release_v2_inventory.InventoryTests.test_at_08_traversal_absolute_symlink_blocks"),
    9: ("test_release_v2_inventory.InventoryTests.test_at_09_distinct_portable_paths_are_accepted", "test_release_v2_inventory.InventoryTests.test_at_09_casefold_collision_blocks"),
    10: ("test_release_v2_identity.IdentityTests.test_at_10_matching_target_profile_toolchain_is_accepted", "test_release_v2_identity.IdentityTests.test_at_10_wrong_target_profile_toolchain_blocks"),
    11: ("test_release_v2_inventory.InventoryTests.test_at_11_matching_artifact_digest_is_accepted", "test_release_v2_inventory.InventoryTests.test_at_11_altered_artifact_blocks"),
    12: ("test_release_v2_inventory.InventoryTests.test_at_12_declared_artifact_is_present", "test_release_v2_inventory.InventoryTests.test_at_12_missing_artifact_blocks"),
    13: ("test_release_v2_inventory.InventoryTests.test_at_13_declared_inventory_has_no_extra_file", "test_release_v2_inventory.InventoryTests.test_at_13_unexpected_artifact_blocks"),
    14: ("test_release_v2_inventory.InventoryTests.test_at_14_canonical_checksums_are_accepted", "test_release_v2_inventory.InventoryTests.test_at_14_malformed_or_duplicate_checksum_blocks"),
    15: ("test_release_v2_inventory.InventoryTests.test_at_15_allowed_executable_mode_is_accepted", "test_release_v2_inventory.InventoryTests.test_at_15_wrong_executable_mode_blocks"),
    16: ("test_release_v2_inventory.InventoryTests.test_at_16_readonly_verifier_preserves_bytes", "test_release_v2_inventory.InventoryTests.test_at_16_detected_input_mutation_blocks"),
    17: ("test_release_v2_inventory.InventoryTests.test_at_17_two_archives_are_byte_equal", "test_release_v2_inventory.InventoryTests.test_at_17_nondeterministic_archive_blocks"),
    18: ("test_release_v2_dependencies.DependencyTests.test_at_18_complete_cargo_pnpm_inventory", "test_release_v2_dependencies.DependencyTests.test_at_18_missing_direct_or_transitive_dependency_blocks"),
    19: ("test_release_v2_dependencies.DependencyTests.test_at_19_complete_transitive_closure_is_accepted", "test_release_v2_dependencies.DependencyTests.test_at_19_missing_closure_member_blocks"),
    20: ("test_release_v2_sbom_acceptance.SbomAcceptanceTests.test_at_20_unique_bom_refs_are_accepted", "test_release_v2_sbom_acceptance.SbomAcceptanceTests.test_at_20_duplicate_bom_ref_blocks"),
    21: ("test_release_v2_dependencies.DependencyTests.test_at_21_pinned_git_dependency_is_accepted", "test_release_v2_dependencies.DependencyTests.test_at_21_unpinned_git_dependency_blocks"),
    22: ("test_release_v2_dependencies.DependencyTests.test_at_22_credential_free_registry_locator_is_accepted", "test_release_v2_dependencies.DependencyTests.test_at_22_registry_credential_url_is_redacted_and_blocks"),
    23: ("test_release_v2_legal.LicenseTests.test_at_23_known_license_policy_is_accepted", "test_release_v2_legal.LicenseTests.test_at_23_unknown_license_blocks"),
    24: ("test_release_v2_sbom_acceptance.SbomAcceptanceTests.test_at_24_sbom_bound_to_candidate_is_accepted", "test_release_v2_sbom_acceptance.SbomAcceptanceTests.test_at_24_sbom_candidate_mismatch_blocks"),
    25: ("test_release_v2_sbom_acceptance.SbomAcceptanceTests.test_at_25_bytewise_sorted_sbom_is_accepted", "test_release_v2_sbom_acceptance.SbomAcceptanceTests.test_at_25_unsorted_sbom_blocks"),
    26: ("test_release_v2_legal.LicenseTests.test_at_26_allowed_license_is_accepted", "test_release_v2_legal.LicenseTests.test_at_26_denied_license_blocks"),
    27: ("test_release_v2_legal.LicenseTests.test_at_27_denied_license_is_reported", "test_release_v2_legal.LicenseTests.test_at_27_denied_license_cannot_be_overridden"),
    28: ("test_release_v2_legal.LicenseTests.test_at_28_complete_license_evidence_is_accepted", "test_release_v2_legal.LicenseTests.test_at_28_unknown_or_missing_license_evidence_blocks"),
    29: ("test_release_v2_legal.LicenseTests.test_at_29_independently_reviewed_unexpired_exception_is_accepted", "test_release_v2_legal.LicenseTests.test_at_29_exception_without_owner_or_expiry_blocks"),
    30: ("test_release_v2_advisory_acceptance.AdvisoryAcceptanceTests.test_at_30_not_affected_advisory_is_accepted", "test_release_v2_advisory_acceptance.AdvisoryAcceptanceTests.test_at_30_advisory_blocked"),
    31: ("test_release_v2_advisory_acceptance.AdvisoryAcceptanceTests.test_at_31_fresh_authenticated_advisory_is_accepted", "test_release_v2_advisory_acceptance.AdvisoryAcceptanceTests.test_at_31_missing_or_stale_advisory_blocks"),
    32: ("test_release_v2_advisory_acceptance.AdvisoryAcceptanceTests.test_at_32_exactly_bound_accepted_risk_is_accepted", "test_release_v2_advisory_acceptance.AdvisoryAcceptanceTests.test_at_32_accepted_risk_wrong_binding_blocks"),
    33: ("test_release_v2_evidence.EvidenceTests.test_at_33_fixture_scan_is_structural_only", "test_release_v2_evidence_acceptance.EvidenceAcceptanceTests.test_at_33_fixture_scan_is_not_production"),
    34: ("test_release_v2_evidence.EvidenceTests.test_at_34_complete_hosted_lane_is_accepted_as_record", "test_release_v2_evidence_acceptance.EvidenceAcceptanceTests.test_at_34_missing_hosted_lane_blocks"),
    35: ("test_release_v2_evidence.EvidenceTests.test_at_35_actual_hosted_attestation_is_typed", "test_release_v2_evidence_acceptance.EvidenceAcceptanceTests.test_at_35_planned_lane_is_not_actual"),
    36: ("test_release_v2_evidence.EvidenceTests.test_at_36_subject_bound_evidence_is_accepted", "test_release_v2_evidence_acceptance.EvidenceAcceptanceTests.test_at_36_wrong_candidate_evidence_blocks"),
    37: ("test_release_v2_evidence.EvidenceTests.test_at_37_unique_fresh_evidence_is_accepted", "test_release_v2_evidence_acceptance.EvidenceAcceptanceTests.test_at_37_duplicate_or_stale_evidence_blocks"),
    38: ("test_release_v2_evidence.EvidenceTests.test_at_38_independent_review_is_accepted_as_fixture_structure", "test_release_v2_evidence_acceptance.EvidenceAcceptanceTests.test_at_38_self_review_rejected"),
    39: ("test_release_v2_evidence.ClaimTests.test_at_39_fixture_claims_are_never_verified", "test_release_v2_claim_acceptance.ClaimAcceptanceTests.test_at_39_fixture_verified_disposition_blocks"),
    40: ("test_release_v2_evidence.ClaimTests.test_at_40_each_known_claim_has_one_disposition", "test_release_v2_claim_acceptance.ClaimAcceptanceTests.test_at_40_duplicate_claim_disposition_blocks"),
    41: ("test_release_v2_evidence.ClaimTests.test_at_41_current_claim_statuses_match_contract", "test_release_v2_claim_acceptance.ClaimAcceptanceTests.test_at_41_unknown_or_escalated_claim_blocks"),
    42: ("test_release_v2_evidence.ClaimTests.test_at_42_fixture_result_is_structural_valid_and_blocked_evidence", "test_release_v2_claim_acceptance.ClaimAcceptanceTests.test_at_42_production_gate_fails_closed_nonzero"),
    43: ("test_release_v2_release_docs.ReleaseDocumentsTests.test_at_43_bound_changelog_and_notes_are_accepted", "test_release_v2_release_docs.ReleaseDocumentsTests.test_at_43_unbound_changelog_or_notes_blocks"),
    44: ("test_release_v2_release_docs.ReleaseDocumentsTests.test_at_44_rollback_preflight_is_not_run", "test_release_v2_release_docs.ReleaseDocumentsTests.test_at_44_rollback_claim_or_invalid_binding_blocks"),
    45: ("test_release_v2_release_docs.ReleaseDocumentsTests.test_at_45_clean_pr_merge_checklists_are_accepted", "test_release_v2_release_docs.ReleaseDocumentsTests.test_at_45_pr_merge_gate_blocks_violation"),
    46: ("test_release_v2_release_docs.ReleaseDocumentsTests.test_at_46_structural_package_has_no_production_command", "test_release_v2_release_docs.ReleaseDocumentsTests.test_at_46_production_action_command_blocks"),
    47: ("test_release_v2_release_docs.ReleaseDocumentsTests.test_at_47_relative_redacted_markers_are_accepted", "test_release_v2_release_docs.ReleaseDocumentsTests.test_at_47_secret_or_absolute_marker_blocks"),
    48: ("test_release_v2_release_docs.ReleaseDocumentsTests.test_at_48_fixture_verification_preserves_bytes", "test_release_v2_release_docs.ReleaseDocumentsTests.test_at_48_post_verification_byte_change_blocks"),
}


def validate_acceptance_registry() -> None:
    if tuple(ACCEPTANCE_REGISTRY) != tuple(range(1, 49)):
        raise AssertionError("acceptance IDs must be 1..48 without gaps")
    identifiers = tuple(item for pair in ACCEPTANCE_REGISTRY.values() for item in pair)
    if len(identifiers) != 96 or len(set(identifiers)) != len(identifiers):
        raise AssertionError("acceptance test IDs must be unique pairs")
    callables = []
    for identifier in identifiers:
        module, class_name, method = identifier.split(".")
        suite = import_module(f"scripts.tests.{module}")
        target = getattr(getattr(suite, class_name), method, None)
        if not callable(target):
            raise AssertionError(f"missing acceptance test: {identifier}")
        _require_real_test_body(target, identifier)
        callables.append(target)
    if len({id(target) for target in callables}) != 96:
        raise AssertionError("acceptance tests must resolve to 96 distinct callables")


def _require_real_test_body(target: object, identifier: str) -> None:
    source = inspect.getsource(target)
    tree = ast.parse(textwrap.dedent(source))
    if ".test_at_" in source or any(isinstance(node, ast.Pass) for node in ast.walk(tree)):
        raise AssertionError(f"acceptance test forwards or has no body: {identifier}")
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
    assertions = [
        node for node in calls if isinstance(node.func, ast.Attribute)
        and (node.func.attr.startswith("assert") or node.func.attr in {"_blocks", "_blocks_with_before"})
    ]
    helpers = [node for node in calls if isinstance(node.func, ast.Name) and node.func.id in {"_blocks", "_sbom_incomplete"}]
    if not assertions and not helpers:
        raise AssertionError(f"acceptance test has no assertion: {identifier}")
