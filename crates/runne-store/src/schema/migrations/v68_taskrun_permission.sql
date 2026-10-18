CREATE TABLE taskrun_local_permission_routes (
 taskrun_id BLOB PRIMARY KEY CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 route INTEGER NOT NULL CHECK(route IN (1,2)),
 provenance INTEGER NOT NULL CHECK(provenance IN (1,2,3)),
 cutover_version INTEGER NOT NULL CHECK(cutover_version=68),
 CHECK((route=1 AND provenance IN (1,2)) OR (route=2 AND provenance=3)),
 FOREIGN KEY(taskrun_id) REFERENCES taskrun_local_command_attempts(taskrun_id) ON DELETE RESTRICT
);
CREATE TABLE x2_permission_bindings (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 fence INTEGER NOT NULL CHECK(fence>0),
 invocation_id BLOB NOT NULL UNIQUE CHECK(length(invocation_id)=16 AND invocation_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 codec_version INTEGER NOT NULL CHECK(codec_version=1),
 binding BLOB NOT NULL CHECK(length(binding) BETWEEN 1 AND 1048576),
 native_owner_id BLOB NOT NULL CHECK(length(native_owner_id)=16 AND native_owner_id!=zeroblob(16)),
 native_owner_generation BLOB NOT NULL CHECK(length(native_owner_generation)=8 AND native_owner_generation!=zeroblob(8)),
 selection_managed_policy_version INTEGER NOT NULL CHECK(selection_managed_policy_version>=0),
 selection_managed_policy_digest BLOB NOT NULL CHECK(length(selection_managed_policy_digest)=32),
 captured_at INTEGER NOT NULL CHECK(captured_at>0),
 PRIMARY KEY(taskrun_id,attempt_id),
 UNIQUE(taskrun_id,attempt_id,binding_digest),
 FOREIGN KEY(taskrun_id) REFERENCES taskrun_local_command_attempts(taskrun_id) ON DELETE RESTRICT,
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence) ON DELETE RESTRICT
);
CREATE TABLE x2_permission_human (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 proof_digest BLOB NOT NULL CHECK(length(proof_digest)=32 AND proof_digest!=zeroblob(32)),
 approval_digest BLOB NOT NULL CHECK(length(approval_digest)=32 AND approval_digest!=zeroblob(32)),
 approval_id BLOB NOT NULL CHECK(length(approval_id)=16 AND approval_id!=zeroblob(16)),
 accepted_at INTEGER NOT NULL CHECK(accepted_at>0),
 PRIMARY KEY(taskrun_id,attempt_id,proof_digest),
 FOREIGN KEY(taskrun_id,attempt_id,binding_digest)
   REFERENCES x2_permission_bindings(taskrun_id,attempt_id,binding_digest) ON DELETE RESTRICT
);
CREATE TABLE x2_permission_admission (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 admission_kind INTEGER NOT NULL CHECK(admission_kind IN (1,2)),
 proof_digest BLOB CHECK(proof_digest IS NULL OR length(proof_digest)=32),
 admitted_at INTEGER NOT NULL CHECK(admitted_at>0),
 PRIMARY KEY(taskrun_id,attempt_id),
 UNIQUE(taskrun_id,attempt_id,binding_digest),
 CHECK((admission_kind=1 AND proof_digest IS NULL) OR
       (admission_kind=2 AND proof_digest IS NOT NULL)),
 FOREIGN KEY(taskrun_id,attempt_id,binding_digest)
   REFERENCES x2_permission_bindings(taskrun_id,attempt_id,binding_digest) ON DELETE RESTRICT,
 FOREIGN KEY(taskrun_id,attempt_id,proof_digest)
   REFERENCES x2_permission_human(taskrun_id,attempt_id,proof_digest) ON DELETE RESTRICT
);
CREATE TABLE x2_permission_spent (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 invocation_id BLOB NOT NULL UNIQUE CHECK(length(invocation_id)=16),
 area_identity BLOB NOT NULL CHECK(length(area_identity)=100),
 owner_id BLOB NOT NULL CHECK(length(owner_id)=16 AND owner_id!=zeroblob(16)),
 owner_generation BLOB NOT NULL CHECK(length(owner_generation)=8 AND owner_generation!=zeroblob(8)),
 burn_id BLOB NOT NULL UNIQUE CHECK(length(burn_id)=16 AND burn_id!=zeroblob(16)),
 burned_at INTEGER NOT NULL CHECK(burned_at>0),
 PRIMARY KEY(taskrun_id,attempt_id),
 UNIQUE(taskrun_id,attempt_id,binding_digest),
 FOREIGN KEY(taskrun_id,attempt_id,binding_digest)
   REFERENCES x2_permission_admission(taskrun_id,attempt_id,binding_digest) ON DELETE RESTRICT
);
CREATE TABLE x2_permission_stop (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 stop_id BLOB NOT NULL UNIQUE CHECK(length(stop_id)=16),
 reason INTEGER NOT NULL CHECK(reason IN (1,2,3,4,5,6)),
 observed_version INTEGER NOT NULL CHECK(observed_version>0),
 event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=16),
 stopped_at INTEGER NOT NULL CHECK(stopped_at>0),
 PRIMARY KEY(taskrun_id,attempt_id),
 FOREIGN KEY(taskrun_id,attempt_id,binding_digest)
   REFERENCES x2_permission_bindings(taskrun_id,attempt_id,binding_digest) ON DELETE RESTRICT,
 FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE RESTRICT
);
CREATE TABLE x2_permission_terminal (
 taskrun_id BLOB NOT NULL CHECK(length(taskrun_id)=16 AND taskrun_id!=zeroblob(16)),
 attempt_id BLOB NOT NULL CHECK(length(attempt_id)=16 AND attempt_id!=zeroblob(16)),
 binding_digest BLOB NOT NULL CHECK(length(binding_digest)=32 AND binding_digest!=zeroblob(32)),
 terminal_kind INTEGER NOT NULL CHECK(terminal_kind IN (1,2)),
 exit_kind INTEGER CHECK(exit_kind IS NULL OR exit_kind IN (1,2)),
 exit_code INTEGER CHECK(exit_code IS NULL OR exit_code BETWEEN 0 AND 255),
 signal INTEGER CHECK(signal IS NULL OR signal BETWEEN 1 AND 64),
 stdout BLOB NOT NULL CHECK(length(stdout)<=65536),
 stderr BLOB NOT NULL CHECK(length(stderr)<=65536),
 stdout_observed INTEGER NOT NULL CHECK(stdout_observed>=length(stdout)),
 stderr_observed INTEGER NOT NULL CHECK(stderr_observed>=length(stderr)),
 stdout_eof INTEGER NOT NULL CHECK(stdout_eof IN (0,1)),
 stderr_eof INTEGER NOT NULL CHECK(stderr_eof IN (0,1)),
 stdout_truncated INTEGER NOT NULL CHECK(stdout_truncated IN (0,1)),
 stderr_truncated INTEGER NOT NULL CHECK(stderr_truncated IN (0,1)),
 area_empty INTEGER NOT NULL CHECK(area_empty IN (0,1)),
 event_id BLOB NOT NULL UNIQUE CHECK(length(event_id)=16 AND event_id!=zeroblob(16)),
 fence INTEGER NOT NULL CHECK(fence>0),
 terminal_version INTEGER NOT NULL CHECK(terminal_version>0),
 settled_at INTEGER NOT NULL CHECK(settled_at>0),
 PRIMARY KEY(taskrun_id,attempt_id),
 CHECK((terminal_kind=1 AND exit_kind=1 AND exit_code IS NOT NULL AND signal IS NULL
        AND area_empty=1 AND stdout_eof=1 AND stderr_eof=1)
    OR (terminal_kind=1 AND exit_kind=2 AND exit_code IS NULL AND signal IS NOT NULL
        AND area_empty=1 AND stdout_eof=1 AND stderr_eof=1)
    OR (terminal_kind=2 AND exit_kind IS NULL AND exit_code IS NULL AND signal IS NULL
        AND stdout=X'' AND stderr=X'' AND stdout_observed=0 AND stderr_observed=0
        AND stdout_eof=1 AND stderr_eof=1 AND stdout_truncated=0 AND stderr_truncated=0
        AND area_empty=1)),
 FOREIGN KEY(taskrun_id,attempt_id,binding_digest)
   REFERENCES x2_permission_bindings(taskrun_id,attempt_id,binding_digest) ON DELETE RESTRICT,
 FOREIGN KEY(taskrun_id,fence) REFERENCES taskrun_assignments(taskrun_id,fence) ON DELETE RESTRICT,
 FOREIGN KEY(event_id) REFERENCES events(event_id) ON DELETE RESTRICT
);
