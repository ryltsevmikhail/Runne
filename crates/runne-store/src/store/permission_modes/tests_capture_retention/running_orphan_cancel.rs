//! Actual library TaskRunService cancellation, never runtime/daemon activation.
use super::{
    fixture::{self, Fixture},
    metadata::Area,
    observations,
};
use crate::store::taskrun_local_command::LocalCommandCancellationStopEvidence;
use runne_application::{
    commands::{CancelTaskRunInput, CommandOutcome},
    ports::*,
    service::TaskRunService,
};
use runne_domain::{
    event::Actor,
    task_run::{TaskRunEvent, TaskRunState},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Requested {
    pub command: String,
    pub key: String,
    pub expected_version: u64,
    pub version: u64,
    pub events: Vec<Vec<u8>>,
}

pub(super) fn request(f: &Fixture, area: &Area) -> Requested {
    let (version, prefix) = observations::stream(&f.store, area, TaskRunState::Running);
    let command = fixture::command_id();
    let key = format!("r05-running-control-{}", area.context.scenario);
    let context = ApplicationCommandContext {
        command_id: command,
        idempotency_key: fixture::key(&key),
        principal_id: PrincipalId(f.principal.as_str().into()),
        actor: Actor::new("capture-test").unwrap(),
    };
    let result = TaskRunService::new(
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
        f.scope.runtime_authority_id.clone(),
    )
    .cancel_task_run(
        &context,
        CancelTaskRunInput {
            taskrun_id: area.identity().taskrun_id,
            expected_version: version,
        },
    )
    .unwrap();
    let CommandOutcome::TaskRunCancellationRequested {
        taskrun_id,
        new_version,
    } = result
    else {
        panic!("actual public cancellation requested")
    };
    assert_eq!(taskrun_id, area.identity().taskrun_id);
    assert_eq!(new_version, version + 1);
    let stream = observations::stream(&f.store, area, TaskRunState::Cancelling);
    assert_eq!(stream.0, new_version);
    assert_eq!(stream.1.len(), prefix.len() + 1);
    assert_eq!(&stream.1[..prefix.len()], prefix.as_slice());
    let loaded = f.store.load_task_run(taskrun_id).unwrap();
    let event = loaded.events.last().unwrap();
    assert!(matches!(
        event.payload(),
        TaskRunEvent::CancellationRequested
    ));
    assert_eq!(event.command_id(), &command);
    assert_eq!(event.idempotency_key(), &context.idempotency_key);
    assert_eq!(
        f.store
            .local_command_cancellation_stop_evidence(taskrun_id, area.identity().attempt_id)
            .unwrap(),
        LocalCommandCancellationStopEvidence::Proven
    );
    Requested {
        command: command.to_string(),
        key,
        expected_version: version,
        version: stream.0,
        events: stream.1,
    }
}
