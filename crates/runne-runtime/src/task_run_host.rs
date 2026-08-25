//! Canonical TaskRun host backed by the runtime command path and event store.

use runne_api::{
    CanonicalTaskRunState, CanonicalTerminalResult, CompleteTaskRunCommand, CreateTaskRunCommand,
    ExistingTaskRunCommand, TaskRunCommandAck, TaskRunCommandAckKind, TaskRunCommandContext,
    TaskRunCommandHostPort, TaskRunHostError, TaskRunQueryHostPort, TaskRunSnapshot,
};
use runne_application::commands::{
    AdmitTaskRunInput, CancelTaskRunInput, CommandOutcome, CompleteTaskRunInput,
    CreateTaskRunInput, QueueTaskRunInput, StartAttemptInput,
};
use runne_application::errors::ApplicationError;
use runne_application::ports::{
    ApplicationCommandContext, EventStore, EventStoreError, PrincipalId,
};
use runne_domain::command::TerminalResult;
use runne_domain::error::DomainError;
use runne_domain::event::Actor;
use runne_domain::task_run::{TaskRun, TaskRunState};

use crate::error::RuntimeError;
use crate::handle::RuntimeHandle;

include!("task_run_host/commands.rs");
include!("task_run_host/query.rs");
include!("task_run_host/helpers.rs");
