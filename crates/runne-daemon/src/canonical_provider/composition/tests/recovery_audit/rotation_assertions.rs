use super::fixture::{Harness, Snapshot, table_columns};

fn column_index(columns: &[String], name: &str) -> usize {
    columns.iter().position(|column| column == name).unwrap()
}

pub(super) fn assert_credential_rotation(
    before: &Snapshot,
    after: &Snapshot,
    harness: &Harness,
    operation_ids: &(String, String),
) {
    let columns = table_columns(harness, "provider_credential_versions");
    let version = column_index(&columns, "credential_version");
    let state = column_index(&columns, "lifecycle_state");
    let lease_fence = column_index(&columns, "lease_fencing_token");
    let revocation = column_index(&columns, "revocation_fence");
    let tombstone = column_index(&columns, "tombstone_digest");
    assert_eq!(before["provider_credential_versions"].len(), 1);
    assert_eq!(after["provider_credential_versions"].len(), 2);
    let provider = column_index(&columns, "provider_id");
    let rotated = after["provider_credential_versions"]
        .iter()
        .filter(|row| row[provider] == "'openai'")
        .collect::<Vec<_>>();
    assert_eq!(rotated.len(), 2);
    let old = rotated[0];
    let replacement = rotated[1];
    assert_eq!(
        (old[version].as_str(), old[state].as_str()),
        ("1", "'DELETED'")
    );
    let original_fence = before["provider_credential_versions"]
        .iter()
        .find(|row| row[provider] == "'openai'")
        .unwrap()[lease_fence]
        .parse::<u64>()
        .unwrap();
    assert_eq!(old[lease_fence], original_fence.to_string());
    assert_eq!(old[revocation], original_fence.to_string());
    assert_ne!(old[tombstone], "NULL");
    assert_eq!(
        (replacement[version].as_str(), replacement[state].as_str()),
        ("2", "'ACTIVE'")
    );
    assert_eq!(replacement[lease_fence], (original_fence + 1).to_string());
    assert_eq!(replacement[revocation], "0");
    assert_eq!(replacement[tombstone], "NULL");

    let head_columns = table_columns(harness, "provider_credential_authority_heads");
    assert_eq!(before["provider_credential_authority_heads"].len(), 1);
    assert_eq!(after["provider_credential_authority_heads"].len(), 1);
    let before_head = &before["provider_credential_authority_heads"][0];
    let after_head = &after["provider_credential_authority_heads"][0];
    for (field, delta) in [
        ("lifecycle_revision", 2),
        ("credential_fence", 2),
        ("readiness_revision", 2),
    ] {
        let index = column_index(&head_columns, field);
        assert_eq!(
            after_head[index].parse::<u64>().unwrap(),
            before_head[index].parse::<u64>().unwrap() + delta
        );
    }
    assert_eq!(
        after_head[column_index(&head_columns, "active_credential_version")],
        "2"
    );

    let operations = &after["provider_credential_operations"];
    assert_eq!(
        operations.len(),
        before["provider_credential_operations"].len() + 2
    );
    let op_columns = table_columns(harness, "provider_credential_operations");
    let action = column_index(&op_columns, "action");
    let state = column_index(&op_columns, "state");
    let operation_id = column_index(&op_columns, "operation_id");
    let pair = operations
        .iter()
        .find(|row| row[operation_id] == operation_ids.0)
        .unwrap();
    let cleanup = operations
        .iter()
        .find(|row| row[operation_id] == operation_ids.1)
        .unwrap();
    assert_eq!(
        (pair[action].as_str(), pair[state].as_str()),
        ("'PAIR'", "'COMPLETED'")
    );
    assert_eq!(
        (cleanup[action].as_str(), cleanup[state].as_str()),
        ("'RETIRED_VERSION_CLEANUP'", "'COMPLETED'")
    );

    let receipts = &after["provider_credential_completion_receipts"];
    assert_eq!(
        receipts.len(),
        before["provider_credential_completion_receipts"].len() + 2
    );
    let receipt_columns = table_columns(harness, "provider_credential_completion_receipts");
    let disposition = column_index(&receipt_columns, "readback_disposition");
    let receipt_operation = column_index(&receipt_columns, "operation_id");
    let pair_receipt = receipts
        .iter()
        .find(|row| row[receipt_operation] == operation_ids.0)
        .unwrap();
    let cleanup_receipt = receipts
        .iter()
        .find(|row| row[receipt_operation] == operation_ids.1)
        .unwrap();
    assert_eq!(pair_receipt[disposition], "'EXACT_VERSION'");
    assert_eq!(cleanup_receipt[disposition], "'EXACT_ABSENCE'");
    for (table, delta) in [
        ("provider_credential_ticket_attempts", 2),
        ("provider_credential_process_attachments", 2),
        ("provider_credential_readiness_observations", 2),
    ] {
        assert_eq!(
            after[table].len(),
            before[table].len() + delta,
            "unexpected {table} transitions"
        );
    }
}
