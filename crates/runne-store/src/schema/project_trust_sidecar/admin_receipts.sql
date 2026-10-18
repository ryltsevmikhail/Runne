CREATE TABLE managed_policy_admin_receipts (
    command_id BLOB PRIMARY KEY CHECK(length(command_id) = 16),
    idempotency_key TEXT NOT NULL CHECK(length(idempotency_key) BETWEEN 1 AND 256),
    stable_subject_digest BLOB NOT NULL CHECK(length(stable_subject_digest) = 32),
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16),
    lineage_id BLOB NOT NULL CHECK(length(lineage_id) = 16),
    project_id BLOB NOT NULL CHECK(length(project_id) = 16),
    instance_epoch INTEGER NOT NULL CHECK(instance_epoch > 0),
    prior_revision INTEGER NOT NULL CHECK(prior_revision > 0),
    revision INTEGER NOT NULL CHECK(revision = prior_revision + 1),
    old_rules_digest BLOB NOT NULL CHECK(length(old_rules_digest) = 32),
    new_rules_digest BLOB NOT NULL CHECK(length(new_rules_digest) = 32),
    command_digest BLOB NOT NULL CHECK(length(command_digest) = 32),
    committed_at_unix_ms INTEGER NOT NULL CHECK(committed_at_unix_ms > 0),
    UNIQUE(stable_subject_digest, idempotency_key),
    FOREIGN KEY(command_id) REFERENCES managed_policy_admin_commands(command_id),
    FOREIGN KEY(stable_subject_digest) REFERENCES managed_policy_administrator(stable_subject_digest)
) STRICT
