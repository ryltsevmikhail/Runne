//! Canonical TaskRun host backed by the runtime command path and event store.

use gocode_api::{
    CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand, CreateTaskRunCommand,
    ExistingTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext,
    TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::errors::ApplicationError;
use gocode_application::ports::{
    ApplicationCommandContext, EventStore, EventStoreError, PrincipalId,
};
use gocode_domain::command::TerminalResult;
use gocode_domain::error::DomainError;
use gocode_domain::event::Actor;
use gocode_domain::task_run::{TaskRun, TaskRunState};

use crate::error::RuntimeError;
use crate::handle::RuntimeHandle;

include!("task_run_host/commands.rs");
include!("task_run_host/query.rs");
include!("task_run_host/helpers.rs");
