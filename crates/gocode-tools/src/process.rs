use gocode_platform::containment::{ContainmentRequest, NativeCertificate, RuntimeProbe};
use gocode_security::broker::process::{
    LaunchedProcess, ProcessBroker, ProcessError, ProcessLauncher, ProcessSpec,
};
use thiserror::Error;

use crate::{
    EffectAdmission, ProcessToolExecutorPort, RawToolOutput, ToolCloseEvidence,
    ToolDispatchRequest, ToolExecutionHandle, ToolExecutorError, ToolExecutorPort,
};

/// Selected process operation supported by Phase 7A.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessOperation {
    /// Execute one structured non-shell command.
    Exec,
    /// PTY remains unavailable without an exact certified profile.
    Pty,
}

/// Complete input for one brokered process start.
pub struct ProcessStartRequest<'a> {
    /// Selected operation.
    pub operation: ProcessOperation,
    /// Structured process specification.
    pub spec: &'a ProcessSpec,
    /// Exact containment request.
    pub containment: &'a ContainmentRequest,
    /// Optional native certificate.
    pub certificate: Option<&'a NativeCertificate>,
    /// Current bounded runtime probes.
    pub probes: &'a [RuntimeProbe],
}

/// Evidence returned by supervised process collection.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ProcessLifecycleReport {
    /// Captured bounded or spill-backed output.
    pub output: RawToolOutput,
    /// Process tree reached a terminal state.
    pub process_terminal: bool,
    /// Containment resources were released.
    pub containment_released: bool,
    /// Cleanup reservation was closed.
    pub cleanup_closed: bool,
    /// Timeout termination was requested.
    pub timed_out: bool,
    /// Cooperative cancellation was requested.
    pub cancelled: bool,
    /// Descendant process count still observed.
    pub remaining_descendants: usize,
    /// Worker generation used to collect evidence.
    pub observed_generation: u64,
}

/// Process execution or lifecycle failure.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum ProcessToolError {
    /// The security broker rejected or could not admit execution.
    #[error(transparent)]
    Broker(#[from] ProcessError),
    /// PTY has no certified production profile.
    #[error("PTY backend unavailable")]
    PtyBackendUnavailable,
    /// Lifecycle evidence belongs to a stale worker generation.
    #[error("stale process lifecycle generation")]
    StaleGeneration,
    /// Descendant cleanup is incomplete.
    #[error("process descendants remain")]
    DescendantsRemain,
}

/// Terminal lifecycle result forwarded into `ToolGateway::close`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcessCloseMaterial {
    /// Exact close evidence.
    pub evidence: ToolCloseEvidence,
    /// Captured output.
    pub output: RawToolOutput,
    /// Whether termination was caused by timeout.
    pub timed_out: bool,
    /// Whether cancellation was requested.
    pub cancelled: bool,
}

/// Selected process executor that can start work only through `ProcessBroker`.
pub struct ProcessToolExecutor {
    broker: ProcessBroker,
}

impl ProcessToolExecutor {
    /// Constructs an executor around the security-owned broker.
    pub const fn new(broker: ProcessBroker) -> Self {
        Self { broker }
    }

    /// Starts an exact structured command through the containment broker.
    pub fn start(
        &self,
        request: ProcessStartRequest<'_>,
        launcher: &dyn ProcessLauncher,
    ) -> Result<LaunchedProcess, ProcessToolError> {
        if request.operation == ProcessOperation::Pty {
            return Err(ProcessToolError::PtyBackendUnavailable);
        }
        self.broker
            .prepare_contained(
                request.spec,
                request.containment,
                request.certificate,
                request.probes,
                launcher,
            )
            .map_err(Into::into)
    }

    /// Validates supervised terminal evidence without inventing cleanup success.
    pub fn close_material(
        expected_generation: u64,
        report: ProcessLifecycleReport,
    ) -> Result<ProcessCloseMaterial, ProcessToolError> {
        if report.observed_generation != expected_generation {
            return Err(ProcessToolError::StaleGeneration);
        }
        if report.remaining_descendants != 0 {
            return Err(ProcessToolError::DescendantsRemain);
        }
        Ok(ProcessCloseMaterial {
            evidence: ToolCloseEvidence {
                process_terminal: report.process_terminal,
                containment_released: report.containment_released,
                cleanup_closed: report.cleanup_closed,
            },
            output: report.output,
            timed_out: report.timed_out,
            cancelled: report.cancelled,
        })
    }
}

impl ToolExecutorPort for ProcessToolExecutor {
    type CompletionMode = crate::ProcessCompletion;

    fn start(
        &self,
        _: &ToolDispatchRequest,
        _: &EffectAdmission,
    ) -> Result<ToolExecutionHandle, ToolExecutorError> {
        Err(ToolExecutorError::Rejected)
    }

    fn signal_cancel(&self, _: &ToolExecutionHandle) -> Result<(), ToolExecutorError> {
        Err(ToolExecutorError::Rejected)
    }
}

impl ProcessToolExecutorPort for ProcessToolExecutor {}
