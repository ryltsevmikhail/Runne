use super::support::Prepared;
use runne_application::ports::{ConversationRepository, EventStore};

type EventFact = ([u8; 16], u64, [u8; 32]);
type StreamHistory = (u64, Vec<EventFact>, u64, Vec<EventFact>);

pub(super) fn stream_history(prepared: &Prepared) -> StreamHistory {
    let taskrun = prepared
        .fixture
        .database
        .store
        .load_task_run(prepared.fixture.taskrun_id)
        .unwrap();
    let conversation = prepared
        .fixture
        .database
        .store
        .load_conversation(super::output_workflow::submitted_conversation(prepared))
        .unwrap();
    (
        taskrun.current_version,
        event_facts(&taskrun.events),
        conversation.current_version,
        event_facts(&conversation.events),
    )
}

fn event_facts<E>(events: &[runne_domain::event::EventEnvelope<E>]) -> Vec<EventFact> {
    events
        .iter()
        .map(|event| {
            (
                *event.event_id().as_bytes(),
                event.sequence(),
                *event.integrity_digest().as_bytes(),
            )
        })
        .collect()
}
