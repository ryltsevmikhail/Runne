CREATE TABLE permission_mode_selections (
 runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16),
 project_id BLOB NOT NULL CHECK(length(project_id)=16),
 selected_mode INTEGER NOT NULL CHECK(selected_mode IN (1,2,3)),
 preset_version INTEGER NOT NULL CHECK(preset_version=1),
 authorization_revision INTEGER NOT NULL CHECK(authorization_revision>0),
 managed_policy_version INTEGER NOT NULL CHECK(managed_policy_version>=0),
 managed_policy_digest BLOB NOT NULL CHECK(length(managed_policy_digest)=32),
 expires_at_unix_ms INTEGER CHECK(expires_at_unix_ms IS NULL OR expires_at_unix_ms>0),
 last_command_id BLOB NOT NULL CHECK(length(last_command_id)=16),
 intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
 updated_at_unix_ms INTEGER NOT NULL CHECK(updated_at_unix_ms>0),
 PRIMARY KEY(runtime_authority_id,principal_id,workspace_id)
);
CREATE TABLE taskrun_tool_permission_admissions (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 cycle_id BLOB NOT NULL CHECK(length(cycle_id)=16),
 proposal_index INTEGER NOT NULL CHECK(proposal_index>=0),
 runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16 AND workspace_id!=zeroblob(16)),
 selected_mode INTEGER NOT NULL CHECK(selected_mode IN (1,2,3)),
 preset_version INTEGER NOT NULL CHECK(preset_version=1),
 authorization_revision INTEGER NOT NULL CHECK(authorization_revision>=0),
 managed_policy_version INTEGER NOT NULL CHECK(managed_policy_version>=0),
 managed_policy_digest BLOB NOT NULL CHECK(length(managed_policy_digest)=32),
 composite_scope_digest BLOB NOT NULL CHECK(length(composite_scope_digest)=32 AND composite_scope_digest!=zeroblob(32)),
 containment INTEGER NOT NULL CHECK(containment IN (1,2)),
 native_scope_handle BLOB NOT NULL CHECK(length(native_scope_handle)=32 AND native_scope_handle!=zeroblob(32)),
 decision_source INTEGER NOT NULL CHECK(decision_source IN (1,2)),
 relevant_policy_digest BLOB NOT NULL CHECK(length(relevant_policy_digest)=32),
 expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>0),
 created_at_unix_ms INTEGER NOT NULL CHECK(created_at_unix_ms>0),
 PRIMARY KEY(taskrun_id,attempt_id,cycle_id,proposal_index),
 FOREIGN KEY(taskrun_id,attempt_id,cycle_id,proposal_index)
   REFERENCES taskrun_tool_invocations(taskrun_id,attempt_id,cycle_id,proposal_index)
   ON DELETE RESTRICT
);
CREATE TRIGGER taskrun_tool_permission_admission_immutable
 BEFORE UPDATE ON taskrun_tool_permission_admissions
 BEGIN SELECT RAISE(ABORT,'tool permission admission is immutable'); END;
CREATE TRIGGER taskrun_tool_permission_admission_no_delete
 BEFORE DELETE ON taskrun_tool_permission_admissions
 BEGIN SELECT RAISE(ABORT,'tool permission admission history is retained'); END;
CREATE TRIGGER permission_mode_selection_insert_revision BEFORE INSERT ON permission_mode_selections
 WHEN NEW.authorization_revision!=1
 BEGIN SELECT RAISE(ABORT,'permission mode selection must start at revision one'); END;
CREATE TRIGGER permission_mode_selection_revision_step BEFORE UPDATE ON permission_mode_selections
 WHEN NEW.runtime_authority_id!=OLD.runtime_authority_id OR NEW.principal_id!=OLD.principal_id
   OR NEW.workspace_id!=OLD.workspace_id OR NEW.authorization_revision!=OLD.authorization_revision+1
 BEGIN SELECT RAISE(ABORT,'permission mode selection identity or revision is invalid'); END;
CREATE TRIGGER permission_mode_selection_no_delete BEFORE DELETE ON permission_mode_selections
 BEGIN SELECT RAISE(ABORT,'permission mode selection history is retained'); END;

CREATE TABLE permission_mode_command_receipts (
 command_id BLOB NOT NULL PRIMARY KEY CHECK(length(command_id)=16),
 runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16),
 project_id BLOB NOT NULL CHECK(length(project_id)=16),
 idempotency_key TEXT NOT NULL CHECK(length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256),
 intent_digest BLOB NOT NULL CHECK(length(intent_digest)=32),
 selected_mode INTEGER NOT NULL CHECK(selected_mode IN (1,2,3)),
 preset_version INTEGER NOT NULL CHECK(preset_version=1),
 authorization_revision INTEGER NOT NULL CHECK(authorization_revision>0),
 managed_policy_version INTEGER NOT NULL CHECK(managed_policy_version>=0),
 managed_policy_digest BLOB NOT NULL CHECK(length(managed_policy_digest)=32),
 expires_at_unix_ms INTEGER CHECK(expires_at_unix_ms IS NULL OR expires_at_unix_ms>0),
 history_projection BLOB NOT NULL CHECK(length(history_projection) BETWEEN 1 AND 4096),
 committed_at_unix_ms INTEGER NOT NULL CHECK(committed_at_unix_ms>0),
 UNIQUE(runtime_authority_id,principal_id,workspace_id,idempotency_key)
);
CREATE TRIGGER permission_mode_receipt_id_global BEFORE INSERT ON permission_mode_command_receipts
 WHEN EXISTS(SELECT 1 FROM command_receipts WHERE command_id=NEW.command_id)
   OR EXISTS(SELECT 1 FROM project_workspace_command_receipts WHERE command_id=NEW.command_id)
 BEGIN SELECT RAISE(ABORT,'permission mode command id already exists'); END;
CREATE TRIGGER permission_mode_command_receipt_immutable BEFORE UPDATE ON permission_mode_command_receipts
 BEGIN SELECT RAISE(ABORT,'permission mode command receipts are immutable'); END;
CREATE TRIGGER permission_mode_command_receipt_no_delete BEFORE DELETE ON permission_mode_command_receipts
 BEGIN SELECT RAISE(ABORT,'permission mode command receipts are retained'); END;
CREATE TRIGGER command_receipt_id_global_d21 BEFORE INSERT ON command_receipts
 WHEN EXISTS(SELECT 1 FROM permission_mode_command_receipts WHERE command_id=NEW.command_id)
 BEGIN SELECT RAISE(ABORT,'command id already exists in permission mode receipts'); END;
CREATE TRIGGER project_workspace_receipt_id_global_d21 BEFORE INSERT ON project_workspace_command_receipts
 WHEN EXISTS(SELECT 1 FROM permission_mode_command_receipts WHERE command_id=NEW.command_id)
 BEGIN SELECT RAISE(ABORT,'command id already exists in permission mode receipts'); END;

CREATE TABLE permission_mode_native_challenges (
 challenge_id BLOB NOT NULL PRIMARY KEY CHECK(length(challenge_id)=16),
 nonce BLOB NOT NULL UNIQUE CHECK(length(nonce)=32),
 challenge_binding_digest BLOB NOT NULL UNIQUE CHECK(length(challenge_binding_digest)=32),
 request_digest BLOB NOT NULL CHECK(length(request_digest)=32),
 command_id BLOB NOT NULL UNIQUE CHECK(length(command_id)=16),
 runtime_authority_id TEXT NOT NULL CHECK(length(runtime_authority_id) BETWEEN 1 AND 256),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 workspace_id BLOB NOT NULL CHECK(length(workspace_id)=16),
 project_id BLOB NOT NULL CHECK(length(project_id)=16),
 workspace_version INTEGER NOT NULL CHECK(workspace_version>0),
 idempotency_key TEXT NOT NULL CHECK(length(CAST(idempotency_key AS BLOB)) BETWEEN 1 AND 256),
 store_authority_id BLOB NOT NULL CHECK(length(store_authority_id)=16 AND store_authority_id!=zeroblob(16)),
 store_lineage_id TEXT NOT NULL CHECK(length(store_lineage_id)=36),
 expected_authorization_revision INTEGER NOT NULL CHECK(expected_authorization_revision>=0),
 preset_version INTEGER NOT NULL CHECK(preset_version=1),
 managed_policy_instance_epoch INTEGER NOT NULL CHECK(managed_policy_instance_epoch>0),
 managed_policy_revision INTEGER NOT NULL CHECK(managed_policy_revision>=0),
 managed_policy_status INTEGER NOT NULL CHECK(managed_policy_status BETWEEN 1 AND 3),
 managed_deny_mask INTEGER NOT NULL CHECK(managed_deny_mask>=0),
 managed_policy_digest BLOB NOT NULL CHECK(length(managed_policy_digest)=32),
 mode_expires_at_unix_ms INTEGER CHECK(mode_expires_at_unix_ms IS NULL OR mode_expires_at_unix_ms>0),
 launch_authority_id BLOB NOT NULL CHECK(length(launch_authority_id)=16 AND launch_authority_id!=zeroblob(16)),
 desktop_host_instance_id BLOB NOT NULL CHECK(length(desktop_host_instance_id)=16 AND desktop_host_instance_id!=zeroblob(16)),
 daemon_instance_id BLOB NOT NULL CHECK(length(daemon_instance_id)=16 AND daemon_instance_id!=zeroblob(16)),
 launch_generation INTEGER NOT NULL CHECK(launch_generation>0),
 native_key_epoch INTEGER NOT NULL CHECK(native_key_epoch>0),
 native_warning_version INTEGER NOT NULL CHECK(native_warning_version=1),
 issued_at_unix_ms INTEGER NOT NULL CHECK(issued_at_unix_ms>0),
 expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>issued_at_unix_ms),
 state INTEGER NOT NULL DEFAULT 1 CHECK(state IN (1,2,3)),
 proof_identifier BLOB CHECK(proof_identifier IS NULL OR length(proof_identifier)=32),
 consumed_at_unix_ms INTEGER CHECK(consumed_at_unix_ms IS NULL OR consumed_at_unix_ms>0),
 UNIQUE(runtime_authority_id,principal_id,workspace_id,idempotency_key),
 CHECK((state=1 AND proof_identifier IS NULL AND consumed_at_unix_ms IS NULL)
    OR (state=2 AND proof_identifier=challenge_binding_digest AND consumed_at_unix_ms IS NOT NULL)
    OR (state=3 AND proof_identifier IS NULL AND consumed_at_unix_ms IS NULL))
);
CREATE INDEX idx_permission_mode_challenges_pending
 ON permission_mode_native_challenges(runtime_authority_id,principal_id,workspace_id,state,expires_at_unix_ms);
CREATE TRIGGER permission_mode_native_challenge_update BEFORE UPDATE ON permission_mode_native_challenges
 WHEN NEW.challenge_id!=OLD.challenge_id OR NEW.nonce!=OLD.nonce
   OR NEW.challenge_binding_digest!=OLD.challenge_binding_digest OR NEW.request_digest!=OLD.request_digest
   OR NEW.command_id!=OLD.command_id OR NEW.runtime_authority_id!=OLD.runtime_authority_id
   OR NEW.principal_id!=OLD.principal_id OR NEW.workspace_id!=OLD.workspace_id OR NEW.project_id!=OLD.project_id
   OR NEW.workspace_version!=OLD.workspace_version OR NEW.idempotency_key!=OLD.idempotency_key
   OR NEW.store_authority_id!=OLD.store_authority_id OR NEW.store_lineage_id!=OLD.store_lineage_id
   OR NEW.expected_authorization_revision!=OLD.expected_authorization_revision
   OR NEW.preset_version!=OLD.preset_version
   OR NEW.managed_policy_instance_epoch!=OLD.managed_policy_instance_epoch
   OR NEW.managed_policy_revision!=OLD.managed_policy_revision OR NEW.managed_policy_status!=OLD.managed_policy_status
   OR NEW.managed_deny_mask!=OLD.managed_deny_mask OR NEW.managed_policy_digest!=OLD.managed_policy_digest
   OR NEW.mode_expires_at_unix_ms IS NOT OLD.mode_expires_at_unix_ms
   OR NEW.launch_authority_id!=OLD.launch_authority_id
   OR NEW.desktop_host_instance_id!=OLD.desktop_host_instance_id
   OR NEW.daemon_instance_id!=OLD.daemon_instance_id OR NEW.launch_generation!=OLD.launch_generation
   OR NEW.native_key_epoch!=OLD.native_key_epoch OR NEW.native_warning_version!=OLD.native_warning_version
   OR NEW.issued_at_unix_ms!=OLD.issued_at_unix_ms OR NEW.expires_at_unix_ms!=OLD.expires_at_unix_ms
   OR OLD.state!=1 OR NEW.state NOT IN (2,3)
 BEGIN SELECT RAISE(ABORT,'permission mode challenge binding is immutable'); END;
CREATE TRIGGER permission_mode_native_challenge_no_delete BEFORE DELETE ON permission_mode_native_challenges
 BEGIN SELECT RAISE(ABORT,'permission mode challenge history is retained'); END;
