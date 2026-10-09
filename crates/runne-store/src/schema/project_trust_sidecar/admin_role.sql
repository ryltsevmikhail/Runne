CREATE TABLE managed_policy_administrator (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    stable_subject_digest BLOB NOT NULL UNIQUE CHECK(length(stable_subject_digest) = 32),
    authority_id BLOB NOT NULL CHECK(length(authority_id) = 16),
    principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
    lineage_id BLOB NOT NULL CHECK(length(lineage_id) = 16),
    profile_id TEXT NOT NULL CHECK(length(profile_id) > 0),
    schema_hash BLOB NOT NULL CHECK(length(schema_hash) = 32),
    capability_digest BLOB NOT NULL CHECK(length(capability_digest) = 32),
    installation_provenance_digest BLOB NOT NULL CHECK(length(installation_provenance_digest) = 32),
    role INTEGER NOT NULL CHECK(role = 1),
    generation INTEGER NOT NULL CHECK(generation > 0),
    status INTEGER NOT NULL CHECK(status IN (1, 2)),
    registered_at_unix_ms INTEGER NOT NULL CHECK(registered_at_unix_ms > 0)
) STRICT
