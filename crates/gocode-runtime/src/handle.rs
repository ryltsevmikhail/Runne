//! Public cloneable handle for submitting commands to the runtime.

use std::sync::Arc;

use gocode_application::commands::{
    AdmitTaskRunInput, CommandOutcome, CompleteTaskRunInput, CreateTaskRunInput, QueueTaskRunInput,
    StartAttemptInput,
};
use gocode_application::ports::ApplicationCommandContext;
use tokio::sync::{mpsc, Semaphore};

use crate::error::{QueueKind, RuntimeError};
use crate::gate::AdmissionGate;
use crate::types::{AdmittedRequest, InFlightLease, Reply, RuntimeRequest};

/// A cloneable, `Send`-able handle for submitting commands to the runtime.
///
/// Created by [`crate::Runtime::start_borrowed`].
pub struct RuntimeHandle {
    sender: mpsc::Sender<AdmittedRequest>,
    gate: Arc<AdmissionGate>,
    in_flight_sem: Arc<Semaphore>,
}

impl Clone for RuntimeHandle {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            gate: Arc::clone(&self.gate),
            in_flight_sem: Arc::clone(&self.in_flight_sem),
        }
    }
}

impl RuntimeHandle {
    pub(crate) fn new(
        sender: mpsc::Sender<AdmittedRequest>,
        gate: Arc<AdmissionGate>,
        in_flight_sem: Arc<Semaphore>,
    ) -> Self {
        Self {
            sender,
            gate,
            in_flight_sem,
        }
    }

    /// Acquire in-flight lease + admission reservation, send request, await reply.
    async fn send_request(
        &self,
        build: impl FnOnce(Reply) -> RuntimeRequest,
    ) -> Result<CommandOutcome, RuntimeError> {
        let in_flight_permit = self
            .in_flight_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RuntimeError::RuntimeClosed)?;
        let lease = InFlightLease::new(in_flight_permit);

        let _reservation = self
            .gate
            .try_reserve()
            .ok_or(RuntimeError::RuntimeClosed)?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = build(reply_tx);
        let admitted = AdmittedRequest { request, lease };

        self.sender.try_send(admitted).map_err(|_| {
            RuntimeError::Backpressure {
                queue: QueueKind::Ingress,
            }
        })?;

        reply_rx
            .await
            .map_err(|_| RuntimeError::RuntimeClosed)
            .and_then(|r| r)
    }

    pub async fn create_task_run(
        &self,
        context: ApplicationCommandContext,
        input: CreateTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::Create {
            context,
            input,
            reply,
        })
        .await
    }

    pub async fn queue_task_run(
        &self,
        context: ApplicationCommandContext,
        input: QueueTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::Queue {
            context,
            input,
            reply,
        })
        .await
    }

    pub async fn admit_task_run(
        &self,
        context: ApplicationCommandContext,
        input: AdmitTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::Admit {
            context,
            input,
            reply,
        })
        .await
    }

    pub async fn start_attempt(
        &self,
        context: ApplicationCommandContext,
        input: StartAttemptInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::StartAttempt {
            context,
            input,
            reply,
        })
        .await
    }

    pub async fn complete_task_run(
        &self,
        context: ApplicationCommandContext,
        input: CompleteTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::Complete {
            context,
            input,
            reply,
        })
        .await
    }
}
