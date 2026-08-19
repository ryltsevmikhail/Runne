pub fn expected_indices(table: &str) -> Option<&'static [&'static str]> {
    match table {
        "drafts" => Some(&[
            "pk:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,2:project_id:0:BINARY:1,3:run_id:0:BINARY:1",
        ]),
        "event_journal" => Some(&[
            "pk:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,2:lineage:0:BINARY:1,3:scope:0:BINARY:1,5:event_id:0:BINARY:1",
            "u:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,2:lineage:0:BINARY:1,3:scope:0:BINARY:1,6:cursor:0:BINARY:1",
            "u:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,2:lineage:0:BINARY:1,3:scope:0:BINARY:1,8:event_sequence:0:BINARY:1",
        ]),
        "meta" => Some(&[]),
        "mutation_ledger" => Some(&[
            "pk:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,2:operation_id:0:BINARY:1",
            "u:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,3:idempotency_key:0:BINARY:1",
        ]),
        "projections" | "replay_cursors" => Some(&[
            "pk:1:0:0:runtime_authority:0:BINARY:1,1:principal:0:BINARY:1,2:lineage:0:BINARY:1,3:scope:0:BINARY:1",
        ]),
        "projects" => Some(&["u:1:0:2:path:0:BINARY:1"]),
        "recent_roots" => Some(&[
            "u:1:0:1:workspace_id:0:BINARY:1",
            "u:1:0:5:native_root_metadata:0:BINARY:1",
            "u:1:0:6:legacy_project_id:0:BINARY:1",
        ]),
        "settings" => Some(&["pk:1:0:0:key:0:BINARY:1"]),
        "window_layout" => Some(&["pk:1:0:0:profile:0:BINARY:1,1:display_topology:0:BINARY:1"]),
        _ => None,
    }
}
