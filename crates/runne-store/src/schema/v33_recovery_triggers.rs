fn v33_attachment_trigger() -> String {
    v29_trigger_source("provider_credential_attachment_insert").replacen(
        "operation.begin_proof_expires_at_high_water > NEW.attached_at",
        "((operation.begin_proof_expires_at_high_water > NEW.attached_at AND NOT EXISTS (SELECT 1 FROM credential_cleanup_recovery_attempts WHERE operation_id=NEW.operation_id)) OR EXISTS (SELECT 1 FROM credential_cleanup_recovery_attempts AS recovery WHERE recovery.operation_id=NEW.operation_id AND recovery.state='ACCEPTED' AND recovery.continuation_digest=NEW.continuation_binding_digest AND recovery.issued_at<=NEW.attached_at AND recovery.expires_at>NEW.attached_at AND recovery.installation_owner_id=operation.installation_owner_id AND recovery.release_tuple_digest=operation.qualified_release_tuple_digest AND recovery.lifecycle_revision=head.lifecycle_revision AND recovery.credential_fence=head.credential_fence))",
        1,
    )
}

fn v33_ticket_trigger() -> String {
    let name = "provider_credential_ticket_insert_issued";
    let source = V24_TRIGGERS.iter().find(|(n, _)| *n == name).expect("ticket trigger exists").1;
    let valid = "EXISTS (SELECT 1 FROM credential_cleanup_recovery_attempts AS recovery WHERE recovery.operation_id=NEW.operation_id AND recovery.state='ACCEPTED' AND recovery.continuation_digest=NEW.continuation_binding_digest AND recovery.issued_at<=NEW.issued_at AND recovery.expires_at>=NEW.expires_at)";
    let old = "(o.begin_proof_expires_at_high_water = 0 OR NEW.issued_at >= o.begin_proof_expires_at_high_water)";
    v25_trigger(name, source)
        .replace(old, &format!("({old} AND NOT {valid})"))
        .replacen(" BEGIN SELECT CASE", &format!(" OR (EXISTS (SELECT 1 FROM credential_cleanup_recovery_attempts WHERE operation_id=NEW.operation_id) AND NOT {valid}) BEGIN SELECT CASE"), 1)
}
