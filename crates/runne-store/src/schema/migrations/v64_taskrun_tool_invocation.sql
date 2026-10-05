
CREATE TABLE taskrun_tool_invocations (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 cycle_id BLOB NOT NULL CHECK(length(cycle_id)=16),
 proposal_index INTEGER NOT NULL CHECK(proposal_index>=0),
 expected_taskrun_version INTEGER NOT NULL CHECK(expected_taskrun_version>0),
 call_id TEXT NOT NULL CHECK(length(call_id) BETWEEN 1 AND 256),
 tool_name TEXT NOT NULL CHECK(length(tool_name) BETWEEN 1 AND 128),
 tool_revision TEXT NOT NULL CHECK(length(tool_revision) BETWEEN 1 AND 128),
 schema_digest BLOB NOT NULL CHECK(length(schema_digest)=32),
 canonical_arguments BLOB NOT NULL CHECK(length(canonical_arguments)<=8208),
 args_key_id BLOB NOT NULL CHECK(length(args_key_id)=16),
 args_key_version INTEGER NOT NULL CHECK(args_key_version>0),
 args_runtime_authority_id BLOB NOT NULL CHECK(length(args_runtime_authority_id)=16),
 args_database_generation INTEGER NOT NULL CHECK(args_database_generation>0),
 args_nonce BLOB NOT NULL CHECK(length(args_nonce)=12),
 args_plaintext_len INTEGER NOT NULL CHECK(args_plaintext_len BETWEEN 1 AND 8192),
 args_plaintext_digest BLOB NOT NULL CHECK(length(args_plaintext_digest)=32),
 arguments_digest BLOB NOT NULL CHECK(length(arguments_digest)=32),
 semantic_digest BLOB NOT NULL CHECK(length(semantic_digest)=32),
 effect_digest BLOB NOT NULL CHECK(length(effect_digest)=32),
 source_refs BLOB NOT NULL CHECK(length(source_refs) BETWEEN 1 AND 8192),
 environment_id TEXT NOT NULL CHECK(length(environment_id) BETWEEN 1 AND 256),
 environment_revision TEXT NOT NULL CHECK(length(environment_revision) BETWEEN 1 AND 256),
 root_identity BLOB NOT NULL CHECK(length(root_identity)=32),
 root_revision INTEGER NOT NULL CHECK(root_revision>0),
 target_name TEXT NOT NULL CHECK(length(target_name) BETWEEN 1 AND 255 AND instr(target_name,'/')=0 AND instr(target_name,'\\')=0 AND target_name NOT IN ('.','..')),
 target_precondition BLOB CHECK(target_precondition IS NULL OR length(target_precondition)=32),
 approval_id BLOB NOT NULL CHECK(length(approval_id)=16),
 principal_id TEXT NOT NULL CHECK(length(principal_id) BETWEEN 1 AND 256),
 approval_principal_id TEXT NOT NULL CHECK(length(approval_principal_id) BETWEEN 1 AND 256),
 approval_action TEXT NOT NULL CHECK(length(approval_action) BETWEEN 1 AND 256),
 approval_resource TEXT NOT NULL CHECK(length(approval_resource) BETWEEN 1 AND 4096),
 approval_digest BLOB NOT NULL CHECK(length(approval_digest)=32),
 policy_revision INTEGER NOT NULL CHECK(policy_revision>0),
 approval_expires_at INTEGER NOT NULL CHECK(approval_expires_at>0),
 round_index INTEGER NOT NULL CHECK(round_index BETWEEN 0 AND 2),
 claim_fence INTEGER CHECK(claim_fence IS NULL OR claim_fence>0),
 claim_node_id TEXT,
 claim_node_epoch INTEGER CHECK(claim_node_epoch IS NULL OR claim_node_epoch>0),
 managed_area_identity BLOB CHECK(managed_area_identity IS NULL OR length(managed_area_identity)=100),
 local_stop_state INTEGER NOT NULL DEFAULT 0 CHECK(local_stop_state IN (0,1,2)),
 empty_proof_identity BLOB CHECK(empty_proof_identity IS NULL OR length(empty_proof_identity)=100),
 release_started INTEGER NOT NULL DEFAULT 0 CHECK(release_started IN (0,1)),
 continuation_started INTEGER NOT NULL DEFAULT 0 CHECK(continuation_started IN (0,1)),
 state TEXT NOT NULL CHECK(state IN ('proposed','approved','denied','claimed','uncertain','result','cancelled','audit_only')),
 helper_receipt_digest BLOB CHECK(helper_receipt_digest IS NULL OR length(helper_receipt_digest)=32),
 helper_receipt_bytes BLOB CHECK(helper_receipt_bytes IS NULL OR length(helper_receipt_bytes)<=16400),
 receipt_key_id BLOB CHECK(receipt_key_id IS NULL OR length(receipt_key_id)=16),
 receipt_key_version INTEGER CHECK(receipt_key_version IS NULL OR receipt_key_version>0),
 receipt_runtime_authority_id BLOB CHECK(receipt_runtime_authority_id IS NULL OR length(receipt_runtime_authority_id)=16),
 receipt_database_generation INTEGER CHECK(receipt_database_generation IS NULL OR receipt_database_generation>0),
 receipt_nonce BLOB CHECK(receipt_nonce IS NULL OR length(receipt_nonce)=12),
 receipt_plaintext_len INTEGER CHECK(receipt_plaintext_len IS NULL OR receipt_plaintext_len BETWEEN 1 AND 16384),
 result_bytes BLOB CHECK(result_bytes IS NULL OR length(result_bytes)<=8192),
 result_digest BLOB CHECK(result_digest IS NULL OR length(result_digest)=32),
 result_length INTEGER CHECK(result_length IS NULL OR result_length>=0),
 result_truncated INTEGER CHECK(result_truncated IS NULL OR result_truncated IN (0,1)),
 updated_at INTEGER NOT NULL CHECK(updated_at>0),
 PRIMARY KEY(taskrun_id,attempt_id,cycle_id,proposal_index),
 UNIQUE(taskrun_id,call_id),
 UNIQUE(taskrun_id,effect_digest),
 CHECK((state IN ('result','audit_only') AND helper_receipt_digest IS NOT NULL AND helper_receipt_bytes IS NOT NULL AND receipt_key_id IS NOT NULL AND receipt_key_version IS NOT NULL AND receipt_runtime_authority_id IS NOT NULL AND receipt_database_generation IS NOT NULL AND receipt_nonce IS NOT NULL AND receipt_plaintext_len IS NOT NULL AND result_bytes IS NULL AND result_digest IS NOT NULL AND result_length IS NOT NULL AND result_truncated IS NOT NULL) OR (state NOT IN ('result','audit_only') AND helper_receipt_digest IS NULL AND helper_receipt_bytes IS NULL AND receipt_key_id IS NULL AND receipt_key_version IS NULL AND receipt_runtime_authority_id IS NULL AND receipt_database_generation IS NULL AND receipt_nonce IS NULL AND receipt_plaintext_len IS NULL AND result_bytes IS NULL AND result_digest IS NULL AND result_length IS NULL AND result_truncated IS NULL))
 ,CHECK((claim_fence IS NULL AND claim_node_id IS NULL AND claim_node_epoch IS NULL AND state IN ('proposed','approved','denied','cancelled')) OR (claim_fence IS NOT NULL AND claim_node_id IS NOT NULL AND claim_node_epoch IS NOT NULL AND state IN ('claimed','uncertain','result','cancelled','audit_only')))
 ,CHECK((local_stop_state=0 AND managed_area_identity IS NULL AND empty_proof_identity IS NULL) OR (local_stop_state=1 AND managed_area_identity IS NOT NULL AND empty_proof_identity IS NULL) OR (local_stop_state=2 AND managed_area_identity IS NOT NULL AND empty_proof_identity=managed_area_identity))
 ,FOREIGN KEY(args_key_id,args_key_version,args_nonce) REFERENCES provider_encryption_nonces(key_id,key_version,nonce)
 ,FOREIGN KEY(receipt_key_id,receipt_key_version,receipt_nonce) REFERENCES provider_encryption_nonces(key_id,key_version,nonce)
);
CREATE TABLE taskrun_provider_round_bindings (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16), fence INTEGER NOT NULL CHECK(fence>0),
 round_index INTEGER NOT NULL CHECK(round_index BETWEEN 0 AND 2), attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 node_id BLOB NOT NULL CHECK(length(node_id)=16), node_epoch INTEGER NOT NULL CHECK(node_epoch>0),
 original_claim_version INTEGER NOT NULL CHECK(original_claim_version>0), current_taskrun_head INTEGER NOT NULL CHECK(current_taskrun_head>0),
 call_id BLOB NOT NULL UNIQUE CHECK(length(call_id)=16), call_digest_version INTEGER NOT NULL CHECK(call_digest_version IN (1,2)),
 prepared_digest BLOB NOT NULL CHECK(length(prepared_digest)=32), render_digest BLOB NOT NULL CHECK(length(render_digest)=32), profile_digest BLOB NOT NULL CHECK(length(profile_digest)=32),
 provider_idempotency_key TEXT NOT NULL UNIQUE CHECK(length(provider_idempotency_key) BETWEEN 1 AND 256),
 previous_attempt_id BLOB CHECK(previous_attempt_id IS NULL OR length(previous_attempt_id)=16), previous_cycle_id BLOB CHECK(previous_cycle_id IS NULL OR length(previous_cycle_id)=16),
 previous_proposal_index INTEGER CHECK(previous_proposal_index IS NULL OR previous_proposal_index>=0), previous_semantic_digest BLOB CHECK(previous_semantic_digest IS NULL OR length(previous_semantic_digest)=32), previous_result_digest BLOB CHECK(previous_result_digest IS NULL OR length(previous_result_digest)=32),
 PRIMARY KEY(taskrun_id,fence,round_index),
 CHECK((round_index=0 AND previous_attempt_id IS NULL AND previous_cycle_id IS NULL AND previous_proposal_index IS NULL AND previous_semantic_digest IS NULL AND previous_result_digest IS NULL) OR (round_index>0 AND previous_attempt_id IS NOT NULL AND previous_cycle_id IS NOT NULL AND previous_proposal_index IS NOT NULL AND previous_semantic_digest IS NOT NULL AND previous_result_digest IS NOT NULL))
);
CREATE TRIGGER taskrun_provider_round_bindings_immutable BEFORE UPDATE ON taskrun_provider_round_bindings BEGIN SELECT RAISE(ABORT,'D2 provider round bindings are append only'); END;
CREATE TRIGGER taskrun_provider_round_bindings_no_delete BEFORE DELETE ON taskrun_provider_round_bindings BEGIN SELECT RAISE(ABORT,'D2 provider round bindings are append only'); END;
CREATE TABLE provider_terminal_application_kinds (
 dispatch_attempt_id BLOB NOT NULL PRIMARY KEY CHECK(length(dispatch_attempt_id)=16),
 outbox_id BLOB NOT NULL UNIQUE CHECK(length(outbox_id)=16),
 application_kind INTEGER NOT NULL CHECK(application_kind IN (1,2)),
 FOREIGN KEY(dispatch_attempt_id) REFERENCES provider_terminal_outbox(dispatch_attempt_id),
 FOREIGN KEY(outbox_id) REFERENCES provider_terminal_outbox(outbox_id)
);
INSERT INTO provider_terminal_application_kinds(dispatch_attempt_id,outbox_id,application_kind)
 SELECT dispatch_attempt_id,outbox_id,1 FROM provider_terminal_outbox;
CREATE TRIGGER provider_terminal_application_kinds_immutable BEFORE UPDATE ON provider_terminal_application_kinds BEGIN SELECT RAISE(ABORT,'provider terminal application kind is immutable'); END;
CREATE TRIGGER provider_terminal_application_kinds_no_delete BEFORE DELETE ON provider_terminal_application_kinds BEGIN SELECT RAISE(ABORT,'provider terminal application kind is append only'); END;
CREATE TABLE d2_tool_loop_completions (
 command_id BLOB NOT NULL PRIMARY KEY CHECK(length(command_id)=16) REFERENCES command_receipts(command_id),
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16), attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 cycle_id BLOB NOT NULL CHECK(length(cycle_id)=16), taskrun_head INTEGER NOT NULL CHECK(taskrun_head>0),
 evaluation_digest BLOB NOT NULL CHECK(length(evaluation_digest)=32),
 terminal_attempt_id BLOB NOT NULL CHECK(length(terminal_attempt_id)=16), terminal_outbox_id BLOB NOT NULL UNIQUE CHECK(length(terminal_outbox_id)=16),
 terminal_sequence INTEGER NOT NULL CHECK(terminal_sequence>=0), settlement_digest BLOB NOT NULL CHECK(length(settlement_digest)=32),
 terminal_sources BLOB NOT NULL CHECK(length(terminal_sources) BETWEEN 1 AND 8192),
 assistant_message_id BLOB NOT NULL CHECK(length(assistant_message_id)=16), assistant_text_digest BLOB NOT NULL CHECK(length(assistant_text_digest)=32),
 completed_receipt_digest BLOB NOT NULL CHECK(length(completed_receipt_digest)=32), created_at INTEGER NOT NULL CHECK(created_at>0),
 UNIQUE(taskrun_id,attempt_id)
);
CREATE TRIGGER d2_tool_loop_completions_immutable BEFORE UPDATE ON d2_tool_loop_completions BEGIN SELECT RAISE(ABORT,'D2 completion linkage is immutable'); END;
CREATE TRIGGER d2_tool_loop_completions_no_delete BEFORE DELETE ON d2_tool_loop_completions BEGIN SELECT RAISE(ABORT,'D2 completion linkage is append only'); END;
CREATE TABLE taskrun_tool_budgets (
 taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id)=16),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16),
 fence INTEGER NOT NULL CHECK(fence>0),
 node_id TEXT NOT NULL CHECK(length(node_id) BETWEEN 1 AND 256),
 node_epoch INTEGER NOT NULL CHECK(node_epoch>0),
 reservation_id BLOB NOT NULL UNIQUE CHECK(length(reservation_id)=16),
 reservation_digest BLOB NOT NULL CHECK(length(reservation_digest)=32),
 policy_revision TEXT NOT NULL CHECK(policy_revision='d2-safe-tool-loop-budget-v1'),
 effects_limit INTEGER NOT NULL CHECK(effects_limit=2),
 continuations_limit INTEGER NOT NULL CHECK(continuations_limit=2),
 effects_used INTEGER NOT NULL CHECK(effects_used BETWEEN 0 AND 2),
 continuations_used INTEGER NOT NULL CHECK(continuations_used BETWEEN 0 AND 2),
 updated_at INTEGER NOT NULL CHECK(updated_at>0)
);
CREATE INDEX idx_taskrun_tool_invocations_state ON taskrun_tool_invocations(taskrun_id,state);
CREATE TRIGGER taskrun_tool_invocations_no_delete BEFORE DELETE ON taskrun_tool_invocations BEGIN SELECT RAISE(ABORT,'tool invocation history is append only'); END;
CREATE TRIGGER taskrun_tool_budgets_no_delete BEFORE DELETE ON taskrun_tool_budgets BEGIN SELECT RAISE(ABORT,'tool budget history is append only'); END;
CREATE TRIGGER taskrun_tool_invocation_binding_immutable BEFORE UPDATE ON taskrun_tool_invocations
 WHEN NEW.taskrun_id!=OLD.taskrun_id OR NEW.attempt_id!=OLD.attempt_id OR NEW.cycle_id!=OLD.cycle_id OR NEW.proposal_index!=OLD.proposal_index OR NEW.expected_taskrun_version!=OLD.expected_taskrun_version OR NEW.call_id!=OLD.call_id OR NEW.tool_name!=OLD.tool_name OR NEW.tool_revision!=OLD.tool_revision OR NEW.schema_digest!=OLD.schema_digest OR NEW.canonical_arguments!=OLD.canonical_arguments OR NEW.args_key_id!=OLD.args_key_id OR NEW.args_key_version!=OLD.args_key_version OR NEW.args_runtime_authority_id!=OLD.args_runtime_authority_id OR NEW.args_database_generation!=OLD.args_database_generation OR NEW.args_nonce!=OLD.args_nonce OR NEW.args_plaintext_len!=OLD.args_plaintext_len OR NEW.args_plaintext_digest!=OLD.args_plaintext_digest OR NEW.arguments_digest!=OLD.arguments_digest OR NEW.semantic_digest!=OLD.semantic_digest OR NEW.effect_digest!=OLD.effect_digest OR NEW.source_refs!=OLD.source_refs OR NEW.environment_id!=OLD.environment_id OR NEW.environment_revision!=OLD.environment_revision OR NEW.root_identity!=OLD.root_identity OR NEW.root_revision!=OLD.root_revision OR NEW.target_name!=OLD.target_name OR NEW.target_precondition IS NOT OLD.target_precondition OR NEW.approval_id!=OLD.approval_id OR NEW.principal_id!=OLD.principal_id OR NEW.approval_principal_id!=OLD.approval_principal_id OR NEW.approval_action!=OLD.approval_action OR NEW.approval_resource!=OLD.approval_resource OR NEW.approval_digest!=OLD.approval_digest OR NEW.policy_revision!=OLD.policy_revision OR NEW.approval_expires_at!=OLD.approval_expires_at OR NEW.round_index!=OLD.round_index OR (OLD.claim_fence IS NOT NULL AND (NEW.claim_fence IS NOT OLD.claim_fence OR NEW.claim_node_id IS NOT OLD.claim_node_id OR NEW.claim_node_epoch IS NOT OLD.claim_node_epoch)) OR (OLD.managed_area_identity IS NOT NULL AND NEW.managed_area_identity IS NOT OLD.managed_area_identity)
 BEGIN SELECT RAISE(ABORT,'tool invocation binding is immutable'); END;
CREATE TRIGGER taskrun_tool_budget_monotonic BEFORE UPDATE ON taskrun_tool_budgets WHEN NEW.effects_used<OLD.effects_used OR NEW.continuations_used<OLD.continuations_used BEGIN SELECT RAISE(ABORT,'tool budgets cannot decrease'); END;
CREATE TRIGGER taskrun_tool_budget_binding_immutable BEFORE UPDATE ON taskrun_tool_budgets WHEN NEW.taskrun_id IS NOT OLD.taskrun_id OR NEW.attempt_id IS NOT OLD.attempt_id OR NEW.fence IS NOT OLD.fence OR NEW.node_id IS NOT OLD.node_id OR NEW.node_epoch IS NOT OLD.node_epoch OR NEW.reservation_id IS NOT OLD.reservation_id OR NEW.reservation_digest IS NOT OLD.reservation_digest OR NEW.policy_revision IS NOT OLD.policy_revision OR NEW.effects_limit IS NOT OLD.effects_limit OR NEW.continuations_limit IS NOT OLD.continuations_limit BEGIN SELECT RAISE(ABORT,'tool budget binding is immutable'); END;
CREATE TRIGGER taskrun_tool_intents_monotonic BEFORE UPDATE ON taskrun_tool_invocations WHEN NEW.release_started<OLD.release_started OR NEW.continuation_started<OLD.continuation_started BEGIN SELECT RAISE(ABORT,'tool release intent cannot be cleared'); END;
CREATE TRIGGER taskrun_tool_area_stop_monotonic BEFORE UPDATE ON taskrun_tool_invocations WHEN NEW.local_stop_state<OLD.local_stop_state OR (OLD.empty_proof_identity IS NOT NULL AND NEW.empty_proof_identity IS NOT OLD.empty_proof_identity) BEGIN SELECT RAISE(ABORT,'tool stop proof is immutable'); END;
CREATE TRIGGER taskrun_tool_receipt_envelope_immutable BEFORE UPDATE ON taskrun_tool_invocations WHEN OLD.receipt_nonce IS NOT NULL AND (NEW.helper_receipt_bytes IS NOT OLD.helper_receipt_bytes OR NEW.receipt_key_id IS NOT OLD.receipt_key_id OR NEW.receipt_key_version IS NOT OLD.receipt_key_version OR NEW.receipt_runtime_authority_id IS NOT OLD.receipt_runtime_authority_id OR NEW.receipt_database_generation IS NOT OLD.receipt_database_generation OR NEW.receipt_nonce IS NOT OLD.receipt_nonce OR NEW.receipt_plaintext_len IS NOT OLD.receipt_plaintext_len) BEGIN SELECT RAISE(ABORT,'tool receipt envelope is immutable'); END;
CREATE TRIGGER taskrun_tool_result_immutable BEFORE UPDATE ON taskrun_tool_invocations WHEN (OLD.result_digest IS NOT NULL OR OLD.receipt_nonce IS NOT NULL) AND (NEW.result_digest IS NOT OLD.result_digest OR NEW.result_length IS NOT OLD.result_length OR NEW.result_truncated IS NOT OLD.result_truncated OR NEW.helper_receipt_bytes IS NOT OLD.helper_receipt_bytes OR NEW.helper_receipt_digest IS NOT OLD.helper_receipt_digest OR NEW.receipt_key_id IS NOT OLD.receipt_key_id OR NEW.receipt_key_version IS NOT OLD.receipt_key_version OR NEW.receipt_runtime_authority_id IS NOT OLD.receipt_runtime_authority_id OR NEW.receipt_database_generation IS NOT OLD.receipt_database_generation OR NEW.receipt_nonce IS NOT OLD.receipt_nonce OR NEW.receipt_plaintext_len IS NOT OLD.receipt_plaintext_len) BEGIN SELECT RAISE(ABORT,'tool result is immutable'); END;
