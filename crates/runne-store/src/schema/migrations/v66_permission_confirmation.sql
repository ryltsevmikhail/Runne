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
 protected_session_id BLOB CHECK(protected_session_id IS NULL OR (length(protected_session_id)=16
   AND protected_session_id!=zeroblob(16) AND substr(lower(hex(protected_session_id)),13,1)='7'
   AND substr(lower(hex(protected_session_id)),17,1) IN ('8','9','a','b'))),
 native_warning_version INTEGER NOT NULL CHECK(native_warning_version>0),
 issued_at_unix_ms INTEGER NOT NULL CHECK(issued_at_unix_ms>0),
 expires_at_unix_ms INTEGER NOT NULL CHECK(expires_at_unix_ms>issued_at_unix_ms),
 state INTEGER NOT NULL DEFAULT 1 CHECK(state IN (1,2,3)),
 proof_identifier BLOB CHECK(proof_identifier IS NULL OR length(proof_identifier)=32),
 consumed_at_unix_ms INTEGER CHECK(consumed_at_unix_ms IS NULL OR consumed_at_unix_ms>0),
 requested_mode INTEGER NOT NULL DEFAULT 3 CHECK(requested_mode IN (1,2,3)),
 digest_version INTEGER NOT NULL DEFAULT 1 CHECK(digest_version IN (1,2)),
 public_request_digest BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
   CHECK(length(public_request_digest)=32),
 confirmation_phase INTEGER NOT NULL DEFAULT 1 CHECK(confirmation_phase IN (1,2,3,4,5)),
 UNIQUE(runtime_authority_id,principal_id,workspace_id,idempotency_key),
 CHECK((digest_version=1 AND protected_session_id IS NULL)
    OR (digest_version=2 AND protected_session_id IS NOT NULL)),
 CHECK(digest_version=1 OR public_request_digest!=zeroblob(32)),
 CHECK((state=1 AND confirmation_phase=1 AND proof_identifier IS NULL AND consumed_at_unix_ms IS NULL)
    OR (state=2 AND confirmation_phase=2 AND proof_identifier IS NOT NULL
        AND proof_identifier=challenge_binding_digest AND consumed_at_unix_ms IS NOT NULL)
    OR (state=3 AND confirmation_phase IN (3,4,5) AND proof_identifier IS NULL AND consumed_at_unix_ms IS NULL))
);

INSERT INTO permission_mode_native_challenges (
 challenge_id,nonce,challenge_binding_digest,request_digest,command_id,runtime_authority_id,
 principal_id,workspace_id,project_id,workspace_version,idempotency_key,store_authority_id,
 store_lineage_id,expected_authorization_revision,preset_version,managed_policy_instance_epoch,
 managed_policy_revision,managed_policy_status,managed_deny_mask,managed_policy_digest,
 mode_expires_at_unix_ms,launch_authority_id,desktop_host_instance_id,daemon_instance_id,
 launch_generation,native_key_epoch,protected_session_id,native_warning_version,issued_at_unix_ms,expires_at_unix_ms,
 state,proof_identifier,consumed_at_unix_ms,requested_mode,digest_version,public_request_digest,
 confirmation_phase
)
SELECT challenge_id,nonce,challenge_binding_digest,request_digest,command_id,runtime_authority_id,
 principal_id,workspace_id,project_id,workspace_version,idempotency_key,store_authority_id,
 store_lineage_id,expected_authorization_revision,preset_version,managed_policy_instance_epoch,
 managed_policy_revision,managed_policy_status,managed_deny_mask,managed_policy_digest,
 mode_expires_at_unix_ms,launch_authority_id,desktop_host_instance_id,daemon_instance_id,
 launch_generation,native_key_epoch,NULL,native_warning_version,issued_at_unix_ms,expires_at_unix_ms,
 CASE WHEN state=1 THEN 3 ELSE state END,proof_identifier,consumed_at_unix_ms,3,1,
 X'0000000000000000000000000000000000000000000000000000000000000000',
 CASE WHEN state=2 THEN 2 ELSE 3 END
FROM permission_mode_native_challenges_v65;

DROP TABLE permission_mode_native_challenges_v65;

CREATE INDEX idx_permission_mode_challenges_pending
 ON permission_mode_native_challenges(runtime_authority_id,principal_id,workspace_id,state,expires_at_unix_ms);

CREATE TRIGGER permission_mode_native_confirmation_v2_update
 BEFORE UPDATE ON permission_mode_native_challenges
 WHEN NEW.requested_mode!=OLD.requested_mode
   OR NEW.digest_version!=OLD.digest_version
   OR NEW.public_request_digest!=OLD.public_request_digest
   OR NEW.protected_session_id IS NOT OLD.protected_session_id
   OR OLD.confirmation_phase!=1
   OR NEW.state NOT IN (2,3)
   OR (NEW.state=2 AND (NEW.confirmation_phase!=2 OR NEW.proof_identifier IS NULL
       OR NEW.proof_identifier!=NEW.challenge_binding_digest
       OR NEW.consumed_at_unix_ms IS NULL))
   OR (NEW.state=3 AND (NEW.confirmation_phase NOT IN (3,4,5)
       OR NEW.proof_identifier IS NOT NULL OR NEW.consumed_at_unix_ms IS NOT NULL))
 BEGIN SELECT RAISE(ABORT,'permission mode confirmation binding is immutable'); END;
