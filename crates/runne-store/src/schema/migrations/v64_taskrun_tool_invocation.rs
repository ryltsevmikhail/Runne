pub(super) const MIGRATION_V64: &str = include_str!("v64_taskrun_tool_invocation.sql");

pub(super) fn apply_v64_migration(connection: &Connection) -> SqliteResult<()> {
    let tx = Transaction::new_unchecked(connection, TransactionBehavior::Exclusive)?;
    tx.execute_batch(MIGRATION_V64)?;
    for table in [
        "taskrun_tool_invocations",
        "taskrun_tool_budgets",
        "provider_terminal_application_kinds",
        "taskrun_provider_round_bindings",
        "d2_tool_loop_completions",
    ] {
        for operation in ["insert", "update", "delete"] {
            tx.execute_batch(&v12_fence_trigger(table, operation).1)?;
        }
    }
    tx.execute("INSERT INTO schema_version(version) VALUES(64)", [])?;
    tx.commit()
}

pub(super) fn v64_matches(connection: &Connection, version: i64) -> SqliteResult<bool> {
    if version < 64
        || !v63_matches(connection, version)?
        || !table_sql_matches_migration(connection, "taskrun_tool_invocations", MIGRATION_V64)?
        || !table_sql_matches_migration(connection, "taskrun_tool_budgets", MIGRATION_V64)?
        || !table_sql_matches_migration(
            connection,
            "taskrun_provider_round_bindings",
            MIGRATION_V64,
        )?
        || !table_sql_matches_migration(
            connection,
            "provider_terminal_application_kinds",
            MIGRATION_V64,
        )?
        || !table_sql_matches_migration(connection, "d2_tool_loop_completions", MIGRATION_V64)?
        || !index_matches(
            connection,
            "idx_taskrun_tool_invocations_state",
            "taskrun_tool_invocations",
            &["taskrun_id", "state"],
        )?
    {
        return Ok(false);
    }
    for (name, sql) in V64_TRIGGERS {
        if !schema_trigger_matches(connection, name, sql)? {
            return Ok(false);
        }
    }
    for table in [
        "taskrun_tool_invocations",
        "taskrun_tool_budgets",
        "provider_terminal_application_kinds",
        "taskrun_provider_round_bindings",
        "d2_tool_loop_completions",
    ] {
        for operation in ["insert", "update", "delete"] {
            let (name, sql) = v12_fence_trigger(table, operation);
            if !schema_trigger_matches(connection, &name, &sql)? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub(super) fn v64_add_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.extend_from_slice(&[
        "taskrun_tool_invocations",
        "taskrun_tool_budgets",
        "provider_terminal_application_kinds",
        "taskrun_provider_round_bindings",
        "d2_tool_loop_completions",
    ]);
    indexes.push("idx_taskrun_tool_invocations_state");
    triggers.extend_from_slice(V64_TRIGGERS);
    for table in [
        "taskrun_tool_invocations",
        "taskrun_tool_budgets",
        "provider_terminal_application_kinds",
        "taskrun_provider_round_bindings",
        "d2_tool_loop_completions",
    ] {
        for operation in ["insert", "update", "delete"] {
            let (name, sql) = v12_fence_trigger(table, operation);
            let static_name = match (table, operation) {
                ("taskrun_tool_invocations", "insert") => {
                    "schema_v12_fence_taskrun_tool_invocations_insert"
                }
                ("taskrun_tool_invocations", "update") => {
                    "schema_v12_fence_taskrun_tool_invocations_update"
                }
                ("taskrun_tool_invocations", "delete") => {
                    "schema_v12_fence_taskrun_tool_invocations_delete"
                }
                ("taskrun_tool_budgets", "insert") => {
                    "schema_v12_fence_taskrun_tool_budgets_insert"
                }
                ("taskrun_tool_budgets", "update") => {
                    "schema_v12_fence_taskrun_tool_budgets_update"
                }
                ("taskrun_tool_budgets", _) => "schema_v12_fence_taskrun_tool_budgets_delete",
                ("provider_terminal_application_kinds", "insert") => {
                    "schema_v12_fence_provider_terminal_application_kinds_insert"
                }
                ("provider_terminal_application_kinds", "update") => {
                    "schema_v12_fence_provider_terminal_application_kinds_update"
                }
                ("provider_terminal_application_kinds", _) => {
                    "schema_v12_fence_provider_terminal_application_kinds_delete"
                }
                ("taskrun_provider_round_bindings", "insert") => {
                    "schema_v12_fence_taskrun_provider_round_bindings_insert"
                }
                ("taskrun_provider_round_bindings", "update") => {
                    "schema_v12_fence_taskrun_provider_round_bindings_update"
                }
                ("taskrun_provider_round_bindings", _) => {
                    "schema_v12_fence_taskrun_provider_round_bindings_delete"
                }
                ("d2_tool_loop_completions", "insert") => {
                    "schema_v12_fence_d2_tool_loop_completions_insert"
                }
                ("d2_tool_loop_completions", "update") => {
                    "schema_v12_fence_d2_tool_loop_completions_update"
                }
                ("d2_tool_loop_completions", _) => {
                    "schema_v12_fence_d2_tool_loop_completions_delete"
                }
                _ => unreachable!("all v64 fence tables and operations are enumerated"),
            };
            let _ = (name, sql);
            triggers.push((static_name, fence_sql(table, operation)));
        }
    }
}

fn fence_sql(table: &str, operation: &str) -> &'static str {
    match (table, operation) {
        ("taskrun_tool_invocations", "insert") => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_invocations_insert\" AFTER INSERT ON \"taskrun_tool_invocations\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_tool_invocations", "update") => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_invocations_update\" AFTER UPDATE ON \"taskrun_tool_invocations\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_tool_invocations", _) => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_invocations_delete\" AFTER DELETE ON \"taskrun_tool_invocations\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_tool_budgets", "insert") => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_budgets_insert\" AFTER INSERT ON \"taskrun_tool_budgets\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_tool_budgets", "update") => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_budgets_update\" AFTER UPDATE ON \"taskrun_tool_budgets\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_tool_budgets", _) => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_tool_budgets_delete\" AFTER DELETE ON \"taskrun_tool_budgets\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_provider_round_bindings", "insert") => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_provider_round_bindings_insert\" AFTER INSERT ON \"taskrun_provider_round_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_provider_round_bindings", "update") => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_provider_round_bindings_update\" AFTER UPDATE ON \"taskrun_provider_round_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("taskrun_provider_round_bindings", _) => {
            "CREATE TRIGGER \"schema_v12_fence_taskrun_provider_round_bindings_delete\" AFTER DELETE ON \"taskrun_provider_round_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("d2_tool_loop_completions", "insert") => {
            "CREATE TRIGGER \"schema_v12_fence_d2_tool_loop_completions_insert\" AFTER INSERT ON \"d2_tool_loop_completions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("d2_tool_loop_completions", "update") => {
            "CREATE TRIGGER \"schema_v12_fence_d2_tool_loop_completions_update\" AFTER UPDATE ON \"d2_tool_loop_completions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("d2_tool_loop_completions", _) => {
            "CREATE TRIGGER \"schema_v12_fence_d2_tool_loop_completions_delete\" AFTER DELETE ON \"d2_tool_loop_completions\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("provider_terminal_application_kinds", "insert") => {
            "CREATE TRIGGER \"schema_v12_fence_provider_terminal_application_kinds_insert\" AFTER INSERT ON \"provider_terminal_application_kinds\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        ("provider_terminal_application_kinds", "update") => {
            "CREATE TRIGGER \"schema_v12_fence_provider_terminal_application_kinds_update\" AFTER UPDATE ON \"provider_terminal_application_kinds\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
        _ => {
            "CREATE TRIGGER \"schema_v12_fence_provider_terminal_application_kinds_delete\" AFTER DELETE ON \"provider_terminal_application_kinds\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END"
        }
    }
}

const V64_TRIGGERS: &[(&str, &str)] = &[
    (
        "d2_tool_loop_completions_immutable",
        "CREATE TRIGGER d2_tool_loop_completions_immutable BEFORE UPDATE ON d2_tool_loop_completions BEGIN SELECT RAISE(ABORT,'D2 completion linkage is immutable'); END",
    ),
    (
        "d2_tool_loop_completions_no_delete",
        "CREATE TRIGGER d2_tool_loop_completions_no_delete BEFORE DELETE ON d2_tool_loop_completions BEGIN SELECT RAISE(ABORT,'D2 completion linkage is append only'); END",
    ),
    (
        "taskrun_provider_round_bindings_immutable",
        "CREATE TRIGGER taskrun_provider_round_bindings_immutable BEFORE UPDATE ON taskrun_provider_round_bindings BEGIN SELECT RAISE(ABORT,'D2 provider round bindings are append only'); END",
    ),
    (
        "taskrun_provider_round_bindings_no_delete",
        "CREATE TRIGGER taskrun_provider_round_bindings_no_delete BEFORE DELETE ON taskrun_provider_round_bindings BEGIN SELECT RAISE(ABORT,'D2 provider round bindings are append only'); END",
    ),
    (
        "taskrun_tool_invocations_no_delete",
        "CREATE TRIGGER taskrun_tool_invocations_no_delete BEFORE DELETE ON taskrun_tool_invocations BEGIN SELECT RAISE(ABORT,'tool invocation history is append only'); END",
    ),
    (
        "taskrun_tool_budgets_no_delete",
        "CREATE TRIGGER taskrun_tool_budgets_no_delete BEFORE DELETE ON taskrun_tool_budgets BEGIN SELECT RAISE(ABORT,'tool budget history is append only'); END",
    ),
    (
        "provider_terminal_application_kinds_immutable",
        "CREATE TRIGGER provider_terminal_application_kinds_immutable BEFORE UPDATE ON provider_terminal_application_kinds BEGIN SELECT RAISE(ABORT,'provider terminal application kind is immutable'); END",
    ),
    (
        "provider_terminal_application_kinds_no_delete",
        "CREATE TRIGGER provider_terminal_application_kinds_no_delete BEFORE DELETE ON provider_terminal_application_kinds BEGIN SELECT RAISE(ABORT,'provider terminal application kind is append only'); END",
    ),
    (
        "taskrun_tool_invocation_binding_immutable",
        "CREATE TRIGGER taskrun_tool_invocation_binding_immutable BEFORE UPDATE ON taskrun_tool_invocations WHEN NEW.taskrun_id!=OLD.taskrun_id OR NEW.attempt_id!=OLD.attempt_id OR NEW.cycle_id!=OLD.cycle_id OR NEW.proposal_index!=OLD.proposal_index OR NEW.expected_taskrun_version!=OLD.expected_taskrun_version OR NEW.call_id!=OLD.call_id OR NEW.tool_name!=OLD.tool_name OR NEW.tool_revision!=OLD.tool_revision OR NEW.schema_digest!=OLD.schema_digest OR NEW.canonical_arguments!=OLD.canonical_arguments OR NEW.args_key_id!=OLD.args_key_id OR NEW.args_key_version!=OLD.args_key_version OR NEW.args_runtime_authority_id!=OLD.args_runtime_authority_id OR NEW.args_database_generation!=OLD.args_database_generation OR NEW.args_nonce!=OLD.args_nonce OR NEW.args_plaintext_len!=OLD.args_plaintext_len OR NEW.args_plaintext_digest!=OLD.args_plaintext_digest OR NEW.arguments_digest!=OLD.arguments_digest OR NEW.semantic_digest!=OLD.semantic_digest OR NEW.effect_digest!=OLD.effect_digest OR NEW.source_refs!=OLD.source_refs OR NEW.environment_id!=OLD.environment_id OR NEW.environment_revision!=OLD.environment_revision OR NEW.root_identity!=OLD.root_identity OR NEW.root_revision!=OLD.root_revision OR NEW.target_name!=OLD.target_name OR NEW.target_precondition IS NOT OLD.target_precondition OR NEW.approval_id!=OLD.approval_id OR NEW.principal_id!=OLD.principal_id OR NEW.approval_principal_id!=OLD.approval_principal_id OR NEW.approval_action!=OLD.approval_action OR NEW.approval_resource!=OLD.approval_resource OR NEW.approval_digest!=OLD.approval_digest OR NEW.policy_revision!=OLD.policy_revision OR NEW.approval_expires_at!=OLD.approval_expires_at OR NEW.round_index!=OLD.round_index OR (OLD.claim_fence IS NOT NULL AND (NEW.claim_fence IS NOT OLD.claim_fence OR NEW.claim_node_id IS NOT OLD.claim_node_id OR NEW.claim_node_epoch IS NOT OLD.claim_node_epoch)) OR (OLD.managed_area_identity IS NOT NULL AND NEW.managed_area_identity IS NOT OLD.managed_area_identity) BEGIN SELECT RAISE(ABORT,'tool invocation binding is immutable'); END",
    ),
    (
        "taskrun_tool_budget_monotonic",
        "CREATE TRIGGER taskrun_tool_budget_monotonic BEFORE UPDATE ON taskrun_tool_budgets WHEN NEW.effects_used<OLD.effects_used OR NEW.continuations_used<OLD.continuations_used BEGIN SELECT RAISE(ABORT,'tool budgets cannot decrease'); END",
    ),
    (
        "taskrun_tool_budget_binding_immutable",
        "CREATE TRIGGER taskrun_tool_budget_binding_immutable BEFORE UPDATE ON taskrun_tool_budgets WHEN NEW.taskrun_id IS NOT OLD.taskrun_id OR NEW.attempt_id IS NOT OLD.attempt_id OR NEW.fence IS NOT OLD.fence OR NEW.node_id IS NOT OLD.node_id OR NEW.node_epoch IS NOT OLD.node_epoch OR NEW.reservation_id IS NOT OLD.reservation_id OR NEW.reservation_digest IS NOT OLD.reservation_digest OR NEW.policy_revision IS NOT OLD.policy_revision OR NEW.effects_limit IS NOT OLD.effects_limit OR NEW.continuations_limit IS NOT OLD.continuations_limit BEGIN SELECT RAISE(ABORT,'tool budget binding is immutable'); END",
    ),
    (
        "taskrun_tool_intents_monotonic",
        "CREATE TRIGGER taskrun_tool_intents_monotonic BEFORE UPDATE ON taskrun_tool_invocations WHEN NEW.release_started<OLD.release_started OR NEW.continuation_started<OLD.continuation_started BEGIN SELECT RAISE(ABORT,'tool release intent cannot be cleared'); END",
    ),
    (
        "taskrun_tool_area_stop_monotonic",
        "CREATE TRIGGER taskrun_tool_area_stop_monotonic BEFORE UPDATE ON taskrun_tool_invocations WHEN NEW.local_stop_state<OLD.local_stop_state OR (OLD.empty_proof_identity IS NOT NULL AND NEW.empty_proof_identity IS NOT OLD.empty_proof_identity) BEGIN SELECT RAISE(ABORT,'tool stop proof is immutable'); END",
    ),
    (
        "taskrun_tool_receipt_envelope_immutable",
        "CREATE TRIGGER taskrun_tool_receipt_envelope_immutable BEFORE UPDATE ON taskrun_tool_invocations WHEN OLD.receipt_nonce IS NOT NULL AND (NEW.helper_receipt_bytes IS NOT OLD.helper_receipt_bytes OR NEW.receipt_key_id IS NOT OLD.receipt_key_id OR NEW.receipt_key_version IS NOT OLD.receipt_key_version OR NEW.receipt_runtime_authority_id IS NOT OLD.receipt_runtime_authority_id OR NEW.receipt_database_generation IS NOT OLD.receipt_database_generation OR NEW.receipt_nonce IS NOT OLD.receipt_nonce OR NEW.receipt_plaintext_len IS NOT OLD.receipt_plaintext_len) BEGIN SELECT RAISE(ABORT,'tool receipt envelope is immutable'); END",
    ),
    (
        "taskrun_tool_result_immutable",
        "CREATE TRIGGER taskrun_tool_result_immutable BEFORE UPDATE ON taskrun_tool_invocations WHEN (OLD.result_digest IS NOT NULL OR OLD.receipt_nonce IS NOT NULL) AND (NEW.result_digest IS NOT OLD.result_digest OR NEW.result_length IS NOT OLD.result_length OR NEW.result_truncated IS NOT OLD.result_truncated OR NEW.helper_receipt_bytes IS NOT OLD.helper_receipt_bytes OR NEW.helper_receipt_digest IS NOT OLD.helper_receipt_digest OR NEW.receipt_key_id IS NOT OLD.receipt_key_id OR NEW.receipt_key_version IS NOT OLD.receipt_key_version OR NEW.receipt_runtime_authority_id IS NOT OLD.receipt_runtime_authority_id OR NEW.receipt_database_generation IS NOT OLD.receipt_database_generation OR NEW.receipt_nonce IS NOT OLD.receipt_nonce OR NEW.receipt_plaintext_len IS NOT OLD.receipt_plaintext_len) BEGIN SELECT RAISE(ABORT,'tool result is immutable'); END",
    ),
];
