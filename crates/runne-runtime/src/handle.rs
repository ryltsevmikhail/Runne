//! Public cloneable handle for submitting commands to the runtime.

use std::sync::Arc;

use runne_application::commands::{
    AdmitTaskRunInput, BeginConversationTextInput, CancelTaskRunInput, CommandOutcome,
    CompleteTaskRunInput, CreateTaskRunInput, FinishConversationTextInput, QueueTaskRunInput,
    StartAttemptInput, SubmitTaskRunInput,
};
use runne_application::ports::{ApplicationCommandContext, TextGenerationReceipt};
use tokio::sync::{Semaphore, mpsc};

use crate::error::{QueueKind, RuntimeError};
use crate::gate::AdmissionGate;
use crate::types::{AdmittedRequest, InFlightLease, Reply, RuntimeRequest};
use crate::{CanonicalProviderExecutionError, CanonicalProviderExecutionJob};

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

        let reservation = self.gate.try_reserve().ok_or(RuntimeError::RuntimeClosed)?;

        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let request = build(reply_tx);
        let admitted = AdmittedRequest { request, lease };

        self.sender
            .try_send(admitted)
            .map_err(|_| RuntimeError::Backpressure {
                queue: QueueKind::Ingress,
            })?;
        // Queue admission is now decided. In-flight work remains tracked by
        // `InFlightLease`; the reservation only bounds producers through the
        // accept-or-reject boundary.
        drop(reservation);

        reply_rx
            .await
            .map_err(|_| RuntimeError::RuntimeClosed)
            .and_then(|r| r)
    }

    async fn send_text_request(
        &self,
        build: impl FnOnce(crate::types::ConversationTextReply) -> RuntimeRequest,
    ) -> Result<TextGenerationReceipt, RuntimeError> {
        let in_flight_permit = self
            .in_flight_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| RuntimeError::RuntimeClosed)?;
        let lease = InFlightLease::new(in_flight_permit);
        let reservation = self.gate.try_reserve().ok_or(RuntimeError::RuntimeClosed)?;
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let admitted = AdmittedRequest {
            request: build(reply_tx),
            lease,
        };
        self.sender
            .try_send(admitted)
            .map_err(|_| RuntimeError::Backpressure {
                queue: QueueKind::Ingress,
            })?;
        drop(reservation);
        reply_rx
            .await
            .map_err(|_| RuntimeError::RuntimeClosed)
            .and_then(|result| result)
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

    /// Submits one TaskRun as a single atomic `Created + Queued` unit-of-work.
    /// The runtime generates the TaskRun id inside the unit-of-work and
    /// returns `TaskRunSubmitted`; no create-then-queue sequence exists.
    pub async fn submit_task_run(
        &self,
        context: ApplicationCommandContext,
        input: SubmitTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::Submit {
            context,
            input,
            reply,
        })
        .await
    }

    /// Executes the published v1 promptless atomic submit.
    pub async fn submit_task_run_legacy(
        &self,
        context: ApplicationCommandContext,
        input: runne_application::commands::LegacySubmitTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::SubmitLegacy {
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

    pub async fn cancel_task_run(
        &self,
        context: ApplicationCommandContext,
        input: CancelTaskRunInput,
    ) -> Result<CommandOutcome, RuntimeError> {
        self.send_request(move |reply| RuntimeRequest::Cancel {
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

    /// Durably appends a user message and starts its coordinated TaskRun.
    pub async fn begin_conversation_text(
        &self,
        context: ApplicationCommandContext,
        input: BeginConversationTextInput,
    ) -> Result<TextGenerationReceipt, RuntimeError> {
        self.send_text_request(move |reply| RuntimeRequest::BeginConversationText {
            context,
            input,
            reply,
        })
        .await
    }

    /// Durably appends assistant output and completes its coordinated TaskRun.
    pub async fn finish_conversation_text(
        &self,
        context: ApplicationCommandContext,
        input: FinishConversationTextInput,
    ) -> Result<TextGenerationReceipt, RuntimeError> {
        self.send_text_request(move |reply| RuntimeRequest::FinishConversationText {
            context,
            input,
            reply,
        })
        .await
    }

    /// Submits one canonical provider job to the runtime supervisor.
    pub async fn execute_canonical_provider(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> Result<TextGenerationReceipt, CanonicalProviderExecutionError> {
        let in_flight_permit = self
            .in_flight_sem
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
        let lease = InFlightLease::new(in_flight_permit);
        let reservation = self
            .gate
            .try_reserve()
            .ok_or(CanonicalProviderExecutionError::Unavailable)?;
        let (reply, waiter) = tokio::sync::oneshot::channel();
        self.sender
            .try_send(AdmittedRequest {
                request: RuntimeRequest::CanonicalProviderExecution { job, reply },
                lease,
            })
            .map_err(|_| CanonicalProviderExecutionError::Unavailable)?;
        drop(reservation);
        waiter
            .await
            .map_err(|_| CanonicalProviderExecutionError::Unavailable)?
    }
}

#[cfg(test)]
mod tests;
