CREATE TABLE permission_mode_native_challenge_managed_identity (
 challenge_id BLOB NOT NULL PRIMARY KEY CHECK(length(challenge_id)=16),
 encoding_tag INTEGER NOT NULL CHECK(encoding_tag=2),
 project_id BLOB NOT NULL CHECK(length(project_id)=16),
 project_version INTEGER NOT NULL CHECK(project_version>0),
 record_instance_epoch INTEGER NOT NULL CHECK(record_instance_epoch>0),
 record_revision INTEGER NOT NULL CHECK(record_revision>=0),
 record_status INTEGER NOT NULL CHECK(record_status BETWEEN 1 AND 3),
 record_deny_mask INTEGER NOT NULL CHECK(record_deny_mask BETWEEN 0 AND 127),
 policy_version INTEGER NOT NULL CHECK(policy_version=1),
 fs_read_decision INTEGER NOT NULL CHECK(fs_read_decision BETWEEN 1 AND 3),
 fs_create_decision INTEGER NOT NULL CHECK(fs_create_decision BETWEEN 1 AND 3),
 fs_write_decision INTEGER NOT NULL CHECK(fs_write_decision BETWEEN 1 AND 3),
 fs_delete_decision INTEGER NOT NULL CHECK(fs_delete_decision BETWEEN 1 AND 3),
 process_start_decision INTEGER NOT NULL CHECK(process_start_decision BETWEEN 1 AND 3),
 network_use_decision INTEGER NOT NULL CHECK(network_use_decision BETWEEN 1 AND 3),
 frozen_policy_version INTEGER NOT NULL CHECK(frozen_policy_version=2),
 local_command_policy_version INTEGER NOT NULL CHECK(local_command_policy_version=1),
 legacy_issued_digest BLOB NOT NULL CHECK(length(legacy_issued_digest)=32),
 canonical_digest BLOB NOT NULL CHECK(length(canonical_digest)=32),
 envelope_digest BLOB NOT NULL CHECK(length(envelope_digest)=32),
 FOREIGN KEY(challenge_id) REFERENCES permission_mode_native_challenges(challenge_id)
   ON DELETE RESTRICT
);

CREATE TABLE permission_mode_command_receipt_managed_identity (
 command_id BLOB NOT NULL PRIMARY KEY CHECK(length(command_id)=16),
 challenge_id BLOB NOT NULL UNIQUE CHECK(length(challenge_id)=16),
 authorization_revision INTEGER NOT NULL CHECK(authorization_revision>0),
 encoding_tag INTEGER NOT NULL CHECK(encoding_tag=2),
 project_version INTEGER NOT NULL CHECK(project_version>0),
 canonical_digest BLOB NOT NULL CHECK(length(canonical_digest)=32),
 envelope_digest BLOB NOT NULL CHECK(length(envelope_digest)=32),
 FOREIGN KEY(command_id) REFERENCES permission_mode_command_receipts(command_id)
   ON DELETE RESTRICT,
 FOREIGN KEY(challenge_id)
   REFERENCES permission_mode_native_challenge_managed_identity(challenge_id)
   ON DELETE RESTRICT
);
