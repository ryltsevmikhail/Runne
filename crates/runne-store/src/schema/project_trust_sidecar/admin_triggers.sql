-- object: trigger managed_policy_admin_immutable_identity
CREATE TRIGGER managed_policy_admin_immutable_identity
BEFORE UPDATE ON managed_policy_administrator
WHEN NEW.id != OLD.id
  OR NEW.stable_subject_digest != OLD.stable_subject_digest
  OR NEW.authority_id != OLD.authority_id
  OR NEW.principal_id != OLD.principal_id
  OR NEW.lineage_id != OLD.lineage_id
  OR NEW.profile_id != OLD.profile_id
  OR NEW.schema_hash != OLD.schema_hash
  OR NEW.capability_digest != OLD.capability_digest
  OR NEW.installation_provenance_digest != OLD.installation_provenance_digest
  OR NEW.role != OLD.role
  OR NEW.registered_at_unix_ms != OLD.registered_at_unix_ms
  OR OLD.status != 1
  OR NEW.status != 2
  OR NEW.generation != OLD.generation + 1
BEGIN
  SELECT RAISE(ABORT, 'managed administrator identity is immutable');
END;

-- object: trigger managed_policy_admin_no_delete
CREATE TRIGGER managed_policy_admin_no_delete
BEFORE DELETE ON managed_policy_administrator
BEGIN
  SELECT RAISE(ABORT, 'managed administrator registration is immutable');
END;

-- object: trigger managed_policy_admin_command_transition
CREATE TRIGGER managed_policy_admin_command_transition
BEFORE UPDATE ON managed_policy_admin_commands
WHEN NEW.command_id != OLD.command_id
  OR NEW.idempotency_key != OLD.idempotency_key
  OR NEW.stable_subject_digest != OLD.stable_subject_digest
  OR NEW.authority_id != OLD.authority_id
  OR NEW.lineage_id != OLD.lineage_id
  OR NEW.project_id != OLD.project_id
  OR NEW.project_epoch != OLD.project_epoch
  OR NEW.expected_revision != OLD.expected_revision
  OR NEW.old_rules_digest != OLD.old_rules_digest
  OR NEW.new_rules_digest != OLD.new_rules_digest
  OR NEW.managed_version != OLD.managed_version
  OR NEW.source_policy_version != OLD.source_policy_version
  OR NEW.local_command_policy_version != OLD.local_command_policy_version
  OR NEW.fs_read != OLD.fs_read
  OR NEW.fs_create != OLD.fs_create
  OR NEW.fs_write != OLD.fs_write
  OR NEW.fs_delete != OLD.fs_delete
  OR NEW.process_start != OLD.process_start
  OR NEW.network_use != OLD.network_use
  OR NEW.admin_generation != OLD.admin_generation
  OR NEW.launch_binding_digest != OLD.launch_binding_digest
  OR NEW.challenge_id != OLD.challenge_id
  OR NEW.challenge_nonce != OLD.challenge_nonce
  OR NEW.warning_version != OLD.warning_version
  OR NEW.issued_at_unix_ms != OLD.issued_at_unix_ms
  OR NEW.expires_at_unix_ms != OLD.expires_at_unix_ms
  OR NEW.request_digest != OLD.request_digest
  OR NEW.semantic_digest != OLD.semantic_digest
  OR NEW.reserved_at_unix_ms != OLD.reserved_at_unix_ms
  OR OLD.state != 1
  OR NEW.state NOT BETWEEN 2 AND 5
BEGIN
  SELECT RAISE(ABORT, 'managed command permits one pending terminal transition');
END;

-- object: trigger managed_policy_admin_command_no_delete
CREATE TRIGGER managed_policy_admin_command_no_delete
BEFORE DELETE ON managed_policy_admin_commands
BEGIN
  SELECT RAISE(ABORT, 'managed command history is immutable');
END;

-- object: trigger managed_policy_admin_receipt_no_update
CREATE TRIGGER managed_policy_admin_receipt_no_update
BEFORE UPDATE ON managed_policy_admin_receipts
BEGIN
  SELECT RAISE(ABORT, 'managed policy receipts are immutable');
END;

-- object: trigger managed_policy_admin_receipt_no_delete
CREATE TRIGGER managed_policy_admin_receipt_no_delete
BEFORE DELETE ON managed_policy_admin_receipts
BEGIN
  SELECT RAISE(ABORT, 'managed policy receipts are immutable');
END;
