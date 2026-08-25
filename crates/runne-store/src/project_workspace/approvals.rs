use runne_api::{
    ApprovalCommandContext, ApprovalCommandHostPort, ApprovalCreateCommand, ApprovalDecision,
    ApprovalDecisionAck, ApprovalDecisionCommand, ApprovalHostError, ApprovalQueryContext,
    ApprovalQueryHostPort, ApprovalRequestHostPort, ApprovalState, ApprovalSummary,
};
use runne_domain::id::{ApprovalId, AttemptId, InvocationId, TaskRunId};
use rusqlite::{OptionalExtension, Transaction, params};

use super::ProjectWorkspaceStore;

#[path = "approval_expiry.rs"]
mod approval_expiry;
use approval_expiry::{expire_pending, unix_millis};

type Row = (
    String,
    String,
    Option<String>,
    String,
    String,
    String,
    String,
    Vec<u8>,
    u64,
    u64,
    u64,
    i64,
    String,
    i64,
    Option<Vec<u8>>,
    Option<String>,
    Option<String>,
    Option<i64>,
    i64,
);

include!("approval_request.rs");
include!("approval_query.rs");
include!("approval_command.rs");
include!("approval_helpers.rs");
