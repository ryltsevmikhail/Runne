//! Runtime controller — shutdown coordination.

use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

pub(crate) fn trace_shutdown_phase(details: std::fmt::Arguments<'_>) {
    if std::env::var_os("RUNNE_SHUTDOWN_TRACE").as_deref() == Some(std::ffi::OsStr::new("1")) {
        use std::io::Write as _;

        let _ = writeln!(std::io::stderr().lock(), "runne_runtime_shutdown {details}");
    }
}

/// How the runtime should shut down.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShutdownMode {
    /// Finish all accepted work, then stop.
    Graceful {
        /// Maximum time to wait for in-flight work to complete.
        timeout: Duration,
    },
    /// Reject queued work immediately, wait for started blocking ops.
    Immediate {
        /// Maximum time to wait for started blocking ops to complete.
        timeout: Duration,
    },
}

/// The outcome of a shutdown operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// All work completed cleanly.
    Quiesced,
    /// Shutdown timed out — some work may remain.
    Incomplete {
        /// Number of workers still active at timeout.
        active_workers: usize,
        /// Number of blocking operations still in progress.
        active_blocking_ops: usize,
        /// Number of commands rejected during shutdown.
        rejected_commands: usize,
    },
}

/// Commands sent from the controller to the supervisor.
pub(crate) enum ControlCommand {
    Shutdown {
        mode: ShutdownMode,
        ack: oneshot::Sender<ShutdownOutcome>,
    },
}

/// The shutdown authority for a running Runne runtime.
///
/// Created by [`crate::Runtime::start_borrowed`].
pub struct RuntimeController {
    control_tx: mpsc::Sender<ControlCommand>,
    drain_complete_rx: Option<oneshot::Receiver<ShutdownOutcome>>,
}

impl RuntimeController {
    pub(crate) fn new(
        control_tx: mpsc::Sender<ControlCommand>,
        drain_complete_rx: oneshot::Receiver<ShutdownOutcome>,
    ) -> Self {
        Self {
            control_tx,
            drain_complete_rx: Some(drain_complete_rx),
        }
    }

    /// Initiate a shutdown with the given mode.
    pub async fn shutdown(&mut self, mode: ShutdownMode) -> ShutdownOutcome {
        let (ack_tx, ack_rx) = oneshot::channel();
        let cmd = ControlCommand::Shutdown { mode, ack: ack_tx };

        trace_shutdown_phase(format_args!("phase=command_send_started mode={mode:?}"));
        if self.control_tx.send(cmd).await.is_err() {
            trace_shutdown_phase(format_args!(
                "phase=command_send_channel_closed outcome=quiesced"
            ));
            return ShutdownOutcome::Quiesced;
        }
        trace_shutdown_phase(format_args!("phase=command_send_completed"));

        match ack_rx.await {
            Ok(outcome) => {
                trace_shutdown_phase(format_args!("phase=ack_received outcome={outcome:?}"));
                outcome
            }
            Err(_) => {
                trace_shutdown_phase(format_args!("phase=ack_channel_closed outcome=quiesced"));
                ShutdownOutcome::Quiesced
            }
        }
    }

    /// Wait for the runtime to fully terminate.
    pub async fn wait_terminated(&mut self) -> ShutdownOutcome {
        if let Some(rx) = self.drain_complete_rx.take() {
            rx.await.unwrap_or(ShutdownOutcome::Quiesced)
        } else {
            ShutdownOutcome::Quiesced
        }
    }
}
