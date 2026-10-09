CREATE TABLE managed_effect_policies (
    project_id BLOB PRIMARY KEY CHECK(length(project_id) = 16),
    policy_version INTEGER NOT NULL CHECK(policy_version = 1),
    fs_read INTEGER NOT NULL CHECK(fs_read BETWEEN 0 AND 2),
    fs_create INTEGER NOT NULL CHECK(fs_create BETWEEN 0 AND 2),
    fs_write INTEGER NOT NULL CHECK(fs_write BETWEEN 0 AND 2),
    fs_delete INTEGER NOT NULL CHECK(fs_delete BETWEEN 0 AND 2),
    process_start INTEGER NOT NULL CHECK(process_start BETWEEN 0 AND 2),
    network_use INTEGER NOT NULL CHECK(network_use BETWEEN 0 AND 2)
)
