use super::super::{ConversationTextCommandService, StoreTransaction};
use runne_application::commands::{
    BeginConversationTextInput, ConversationTextCompletion, FinishConversationTextInput,
};
use runne_application::ports::{
    ApplicationCommandContext, ConversationRepository, EventStore, TaskRunCancellationScanner,
    TaskRunQueueScanRequest, TextGenerationPhase,
};
use runne_domain::conversation::ConversationEvent;
use runne_domain::message::MessageText;

pub(in super::super) fn settle_no_admission_cancellation(
    store: &StoreTransaction,
    text: &dyn ConversationTextCommandService,
    taskrun_id: runne_domain::id::TaskRunId,
    cancellation_version: u64,
) -> Result<bool, ()> {
    let mut cursor = None;
    let mut matched = None;
    loop {
        let request = TaskRunQueueScanRequest::new(cursor, 128).ok_or(())?;
        let page = store
            .scan_pending_taskrun_cancellations(request)
            .map_err(|_| {
                diagnostic("no_admission.scan_cancellations");
            })?;
        for candidate in page.candidates {
            if candidate.taskrun_id == taskrun_id
                && candidate.current_version == cancellation_version
                && matched.replace(candidate).is_some()
            {
                return Err(());
            }
        }
        if page.reached_end {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Err(());
        }
    }
    let Some(candidate) = matched else {
        return Ok(false);
    };
    settle_one_no_admission(store, text, candidate)
}

pub(in super::super) fn recover_all_no_admission_cancellations(
    store: &StoreTransaction,
    text: &dyn ConversationTextCommandService,
) -> Result<usize, ()> {
    let mut cursor = None;
    let mut settled = 0usize;
    loop {
        let request = TaskRunQueueScanRequest::new(cursor, 128).ok_or(())?;
        let page = store
            .scan_pending_taskrun_cancellations(request)
            .map_err(|_| {
                diagnostic("no_admission.recovery_scan");
            })?;
        for candidate in page.candidates {
            if settle_one_no_admission(store, text, candidate)? {
                settled = settled.checked_add(1).ok_or(())?;
            }
        }
        if page.reached_end {
            return Ok(settled);
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            return Err(());
        }
    }
}

fn settle_one_no_admission(
    store: &StoreTransaction,
    text_service: &dyn ConversationTextCommandService,
    candidate: runne_application::ports::TaskRunQueueCandidate,
) -> Result<bool, ()> {
    let taskrun = store.load_task_run(candidate.taskrun_id).map_err(|_| {
        diagnostic("no_admission.load_taskrun");
    })?;
    if taskrun.current_version != candidate.current_version {
        return Ok(false);
    }
    let task = runne_domain::task_run::TaskRun::replay(&taskrun.events).map_err(|_| {
        diagnostic("no_admission.replay_taskrun");
    })?;
    let attempt_id = match (task.state(), task.active_attempt().copied()) {
        (runne_domain::task_run::TaskRunState::Cancelling, Some(attempt)) => attempt,
        _ => return Ok(false),
    };
    if store
        .has_provider_execution_admission_for_attempt(candidate.taskrun_id, attempt_id)
        .map_err(|_| {
            diagnostic("no_admission.check_admission");
        })?
    {
        return Ok(false);
    }
    let started_event = taskrun
        .events
        .get(usize::try_from(candidate.current_version.checked_sub(2).ok_or(())?).map_err(|_| ())?)
        .ok_or(())?;
    if started_event.payload()
        != &(runne_domain::task_run::TaskRunEvent::AttemptStarted { attempt_id })
    {
        return Ok(false);
    }
    let Some(command) = store
        .find_started_text_generation_for_taskrun(candidate.taskrun_id)
        .map_err(|_| {
            diagnostic("no_admission.find_started_text");
        })?
    else {
        return Ok(false);
    };
    if command.receipt.attempt_id != attempt_id
        || command.receipt.taskrun_version != started_event.sequence()
        || command.receipt.phase != TextGenerationPhase::Started
    {
        return Ok(false);
    }
    let conversation = store
        .load_conversation(command.receipt.conversation_id)
        .map_err(|_| {
            diagnostic("no_admission.load_conversation");
        })?;
    if conversation.current_version != command.receipt.conversation_version {
        return Ok(false);
    }
    let mut matching = conversation.events.iter().filter(|event| {
        matches!(event.payload(), ConversationEvent::UserMessageAppended {
            message_id, taskrun_id, attempt_id: event_attempt, ..
        } if *message_id == command.receipt.user_message_id
            && *taskrun_id == candidate.taskrun_id && *event_attempt == attempt_id)
    });
    let event = matching.next().ok_or(())?;
    if matching.next().is_some() {
        return Err(());
    }
    let ConversationEvent::UserMessageAppended { text: prompt, .. } = event.payload() else {
        return Err(());
    };
    if command.receipt.conversation_version != event.sequence() {
        return Err(());
    }
    let context = ApplicationCommandContext {
        command_id: command.command_id,
        idempotency_key: command.idempotency_key,
        principal_id: command.principal_id,
        actor: event.actor().clone(),
    };
    text_service
        .finish_text(
            &context,
            FinishConversationTextInput {
                original: BeginConversationTextInput {
                    conversation_id: command.receipt.conversation_id,
                    expected_version: command
                        .receipt
                        .conversation_version
                        .checked_sub(1)
                        .ok_or(())?,
                    text: MessageText::new(prompt.as_str().to_owned()).map_err(|_| ())?,
                },
                started: command.receipt,
                completion: ConversationTextCompletion::NoProviderAdmissionCancellation {
                    evidence: runne_application::ports::ProviderNoAdmissionCancellationEvidence {
                        cancellation_taskrun_version: candidate.current_version,
                    },
                },
            },
        )
        .map_err(|_| {
            diagnostic("no_admission.finish_text");
        })?;
    Ok(true)
}

fn diagnostic(stage: &'static str) {
    #[cfg(feature = "test-support")]
    eprintln!("runne-daemon-diagnostic stage={stage}");

    #[cfg(not(feature = "test-support"))]
    let _ = stage;
}
