use super::*;
use runne_application::ports::{RuntimeAuthorityId, TaskRunAssignmentIdentity};
use runne_domain::{agent_loop::LoopCycleState, id::TaskRunId, task_run::TaskRun};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

include!("validate/binding_digest.rs");
include!("validate/task_authority.rs");
include!("validate/persistence.rs");
