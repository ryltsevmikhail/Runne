const V52_CREDENTIAL_TABLES: &[&str] = &[
    "provider_secondary_profile_grants",
    "provider_secondary_profile_bindings",
    "provider_secondary_profile_attempts",
];

const V52_CREDENTIAL_INDEXES: &[&str] = &["provider_secondary_profile_bindings_one_active"];

const V52_CREDENTIAL_TRIGGERS: &[(&str, &str)] = &[
    (
        "provider_secondary_profile_grants_identity_immutable",
        "CREATE TRIGGER provider_secondary_profile_grants_identity_immutable BEFORE UPDATE ON provider_secondary_profile_grants WHEN NEW.grant_id!=OLD.grant_id OR NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.database_generation!=OLD.database_generation OR NEW.provider_id!=OLD.provider_id OR NEW.profile_id!=OLD.profile_id OR NEW.credential_realm!=OLD.credential_realm OR NEW.profile_digest!=OLD.profile_digest OR NEW.pricing_revision_digest!=OLD.pricing_revision_digest OR NEW.token_budget_limit!=OLD.token_budget_limit OR NEW.cost_budget_limit_micros!=OLD.cost_budget_limit_micros OR NEW.created_at!=OLD.created_at OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at) OR (OLD.enabled=0 AND NEW.enabled!=0) BEGIN SELECT RAISE(ABORT,'Provider profile grant identity is immutable'); END",
    ),
    (
        "provider_secondary_profile_grants_no_delete",
        "CREATE TRIGGER provider_secondary_profile_grants_no_delete BEFORE DELETE ON provider_secondary_profile_grants BEGIN SELECT RAISE(ABORT,'Provider profile grant is retained'); END",
    ),
    (
        "provider_secondary_profile_bindings_immutable",
        "CREATE TRIGGER provider_secondary_profile_bindings_immutable BEFORE UPDATE ON provider_secondary_profile_bindings WHEN NEW.binding_id!=OLD.binding_id OR NEW.grant_id!=OLD.grant_id OR NEW.owner_id!=OLD.owner_id OR NEW.authority_revision!=OLD.authority_revision OR NEW.scope!=OLD.scope OR NEW.activation_binding_kind!=OLD.activation_binding_kind OR NEW.activation_binding_digest!=OLD.activation_binding_digest OR NEW.created_at!=OLD.created_at OR (OLD.closed_at IS NOT NULL AND (NEW.closed_at IS NOT OLD.closed_at OR NEW.close_reason IS NOT OLD.close_reason)) OR (OLD.closed_at IS NULL AND (NEW.closed_at IS NULL OR NEW.close_reason IS NULL)) BEGIN SELECT RAISE(ABORT,'Provider profile authorization binding is immutable'); END",
    ),
    (
        "provider_secondary_profile_bindings_no_delete",
        "CREATE TRIGGER provider_secondary_profile_bindings_no_delete BEFORE DELETE ON provider_secondary_profile_bindings BEGIN SELECT RAISE(ABORT,'Provider profile binding is retained'); END",
    ),
    (
        "provider_secondary_profile_attempts_immutable",
        "CREATE TRIGGER provider_secondary_profile_attempts_immutable BEFORE UPDATE ON provider_secondary_profile_attempts BEGIN SELECT RAISE(ABORT,'Provider profile attempt binding is immutable'); END",
    ),
    (
        "provider_secondary_profile_attempts_no_delete",
        "CREATE TRIGGER provider_secondary_profile_attempts_no_delete BEFORE DELETE ON provider_secondary_profile_attempts BEGIN SELECT RAISE(ABORT,'Provider profile attempt binding is retained'); END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_grants_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_grants_insert\" AFTER INSERT ON \"provider_secondary_profile_grants\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_grants_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_grants_update\" AFTER UPDATE ON \"provider_secondary_profile_grants\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_grants_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_grants_delete\" AFTER DELETE ON \"provider_secondary_profile_grants\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_bindings_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_bindings_insert\" AFTER INSERT ON \"provider_secondary_profile_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_bindings_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_bindings_update\" AFTER UPDATE ON \"provider_secondary_profile_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_bindings_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_bindings_delete\" AFTER DELETE ON \"provider_secondary_profile_bindings\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_attempts_insert",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_attempts_insert\" AFTER INSERT ON \"provider_secondary_profile_attempts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_attempts_update",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_attempts_update\" AFTER UPDATE ON \"provider_secondary_profile_attempts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
    (
        "schema_v12_fence_provider_secondary_profile_attempts_delete",
        "CREATE TRIGGER \"schema_v12_fence_provider_secondary_profile_attempts_delete\" AFTER DELETE ON \"provider_secondary_profile_attempts\" BEGIN INSERT INTO schema_upgrade_write_latch (id, closed) VALUES (1, 1) ON CONFLICT(id) DO NOTHING; END",
    ),
];

fn v52_add_credential_schema_extensions(
    tables: &mut Vec<&'static str>,
    indexes: &mut Vec<&'static str>,
    triggers: &mut Vec<(&'static str, &'static str)>,
) {
    tables.extend_from_slice(V52_CREDENTIAL_TABLES);
    indexes.extend_from_slice(V52_CREDENTIAL_INDEXES);
    triggers.extend_from_slice(V52_CREDENTIAL_TRIGGERS);
}
