use rusqlite::Connection;

pub fn drop_v42_v43_taskrun_schema(connection: &Connection) -> rusqlite::Result<()> {
    connection.execute_batch(
        "DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignment_occupations_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignment_occupations_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignment_occupations_delete;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignment_lease_renewals_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignment_lease_renewals_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignment_lease_renewals_delete;
         DROP TRIGGER IF EXISTS taskrun_dispatch_intents_immutable;
         DROP TRIGGER IF EXISTS taskrun_dispatch_intents_no_delete;
         DROP TRIGGER IF EXISTS taskrun_occupation_intent_guard;
         DROP TABLE IF EXISTS taskrun_dispatch_intents;
         DROP TABLE IF EXISTS taskrun_assignment_lease_renewals;
         DROP TABLE IF EXISTS taskrun_assignment_occupations;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignments_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignments_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_assignments_delete;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_fence_counters_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_fence_counters_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_fence_counters_delete;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_claim_receipts_insert;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_claim_receipts_update;
         DROP TRIGGER IF EXISTS schema_v12_fence_taskrun_claim_receipts_delete;
         DROP TRIGGER IF EXISTS taskrun_assignments_immutable;
         DROP TRIGGER IF EXISTS taskrun_assignments_no_delete;
         DROP TRIGGER IF EXISTS taskrun_claim_receipts_immutable;
         DROP TRIGGER IF EXISTS taskrun_claim_receipts_no_delete;
         DROP TRIGGER IF EXISTS global_command_id_from_taskrun_claim_receipts;
         DROP TRIGGER IF EXISTS global_command_id_from_lease_renewals_v43;
         DROP TRIGGER IF EXISTS global_command_id_from_command_receipts_v43;
         DROP TRIGGER IF EXISTS global_command_id_from_project_workspace_receipts_v43;
         DROP TRIGGER IF EXISTS global_command_id_from_taskrun_claim_receipts_v43;
         DROP TRIGGER IF EXISTS taskrun_assignment_lease_renewals_immutable;
         DROP TRIGGER IF EXISTS global_command_id_from_command_receipts_v42;
         DROP TRIGGER IF EXISTS global_command_id_from_project_workspace_receipts_v42;
         DROP TABLE IF EXISTS taskrun_claim_receipts;
         DROP TABLE IF EXISTS taskrun_assignments;
         DROP TABLE IF EXISTS taskrun_fence_counters;",
    )
}
