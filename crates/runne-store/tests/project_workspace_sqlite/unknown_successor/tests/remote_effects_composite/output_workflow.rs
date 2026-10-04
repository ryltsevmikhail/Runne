use super::output_helpers::OUTPUT;
use super::support::Prepared;
use runne_application::ports::{ConversationRepository, EventStore};

pub(super) fn assert_running_without_assistant(prepared: &Prepared) {
    let stream = prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap();
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&stream.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Running
    );
    let conversation = submitted_conversation(prepared);
    assert!(
        prepared
            .fixture
            .database
            .store
            .load_conversation(conversation)
            .unwrap()
            .events
            .iter()
            .all(|event| !matches!(
                event.payload(),
                runne_domain::conversation::ConversationEvent::AssistantMessageAppended { taskrun_id, .. }
                    if *taskrun_id == prepared.fixture.taskrun_id
            ))
    );
}

pub(super) fn assert_taskrun_succeeded(prepared: &Prepared) {
    let stream = prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap();
    assert_eq!(
        runne_domain::task_run::TaskRun::replay(&stream.events)
            .unwrap()
            .state(),
        runne_domain::task_run::TaskRunState::Succeeded
    );
}

pub(super) fn assert_assistant_output(prepared: &Prepared) {
    let conversation = submitted_conversation(prepared);
    let events = prepared
        .fixture
        .database
        .store
        .load_conversation(conversation)
        .unwrap()
        .events;
    let matching = events
        .iter()
        .filter_map(|event| match event.payload() {
            runne_domain::conversation::ConversationEvent::AssistantMessageAppended {
                taskrun_id,
                text,
                ..
            } if *taskrun_id == prepared.fixture.taskrun_id => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(matching, [OUTPUT]);
}

pub(super) fn submitted_conversation(prepared: &Prepared) -> runne_domain::id::ConversationId {
    prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap()
        .events
        .iter()
        .find_map(|event| match event.payload() {
            runne_domain::task_run::TaskRunEvent::TaskRunSubmitted {
                conversation_id, ..
            } => Some(*conversation_id),
            _ => None,
        })
        .unwrap()
}
