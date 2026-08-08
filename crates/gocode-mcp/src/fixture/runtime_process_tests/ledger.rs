const PLANNED_CASES: [&str; 18] = [
    "planned_case_registry_has_exact_cardinality",
    "duplicate_reserve_has_one_owner_and_one_busy_without_second_receipt",
    "every_key_field_conflict_is_rejected",
    "refunded_current_entry_is_retained",
    "old_receipt_cannot_refund_or_admit_after_retry",
    "old_receipt_cannot_refund_or_admit_after_terminal_state",
    "overflow_is_atomic",
    "completed_and_uncertain_are_first_wins",
    "validation_success_records_witness_before_commit",
    "validation_error_leaves_reserved_without_replay_then_valid_succeeds",
    "final_validation_panic_poisons_state",
    "witness_assignment_panic_poisons_state",
    "commit_panic_poisons_state",
    "try_audit_reports_poison",
    "legacy_audit_panics_when_state_is_unavailable",
    "audit_stores_only_canonical_metadata",
    "audit_debug_is_sentinel_only",
    "protocol_audit_remains_available",
];

mod admission;
mod audit;
mod material;
mod reservation;
mod support;

#[test]
fn planned_case_registry_has_exact_cardinality() {
    assert_eq!(PLANNED_CASES.len(), 18);
}
