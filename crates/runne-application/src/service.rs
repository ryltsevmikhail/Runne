//! Public application facade — the only entry point for callers.
//!
//! [`TaskRunService`] owns the pipeline and exposes five typed use cases.

use runne_domain::agent_loop::{LoopCheckpointBody, LoopDisposition};
use runne_domain::command::TaskRunCommand;
use runne_domain::task_run::TaskRunState;
use runne_domain::verification::PlanEvaluationResult;

use crate::commands::{
    ActivateScheduledRetryInput, AdmitTaskRunInput, CancelTaskRunInput, CommandOutcome,
    CommitContextInput, CommitLoopCheckpointInput, CommitPlanInput, CommitRecoveryResumeInput,
    CompleteLoopCycleInput, CompleteTaskRunInput, CreateNextCycleInput, CreateTaskRunInput,
    QueueTaskRunInput, RecordStepOutcomeInput, ResumeLoopWaitInput, ScheduleRetryInput,
    StartAttemptInput, StartLoopCycleInput, SubmitTaskRunInput,
};
use crate::errors::ApplicationError;
use crate::fingerprint::{CommandFingerprint, checkpoint_body_digest};
use crate::pipeline::Pipeline;
use crate::ports::{
    ApplicationCommandContext, EventStore, IdGenerator, OperationTag, ReconciliationQueryPort,
    RetrySchedulePort, RuntimeAuthorityId, TimePort, UnitOfWork, VerificationQueryPort,
    WakeEvidenceQueryPort,
};

include!("service_types.rs");
include!("service_constructors.rs");
include!("service_basic.rs");
include!("service_taskrun_claim.rs");
include!("service_loop_start.rs");
include!("service_loop_control.rs");
include!("service_loop_retry.rs");

#[cfg(test)]
mod tests {
    include!("tests/support.rs");
    include!("tests/duplicate_retry.rs");
    include!("tests/authority_support.rs");
    include!("tests/wake.rs");
    include!("tests/time.rs");
    include!("tests/verification.rs");
}
