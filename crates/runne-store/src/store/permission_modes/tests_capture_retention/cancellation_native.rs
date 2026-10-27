use super::{
    budget::Deadline,
    fixture::{self, Fixture},
    metadata::Area,
    observations, receipts, records,
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
use runne_platform::local_command_linux::PermissionChildV1;
use std::{path::Path, time::Duration};

pub(super) struct OwnedNative<'a> {
    pub child: PermissionChildV1<'a>,
    pub deadline: Deadline,
}
impl Drop for OwnedNative<'_> {
    fn drop(&mut self) {
        // Unwind only; exact owned handle, no guessed PID or successful removal fallback.
        let _ = self.child.terminate_area(Duration::from_millis(20));
        let _ = self.child.reap_after_stop(Duration::from_secs(2));
    }
}
pub(super) fn output(child: &mut OwnedNative<'_>, bytes: &mut Vec<u8>, eof: bool) {
    let phase = child.deadline.phase();
    loop {
        phase.check();
        child.child.poll_output().unwrap();
        let c = child.child.take_output();
        bytes.extend_from_slice(&c.stdout);
        assert!(b"ready".starts_with(bytes.as_slice()));
        assert!(c.stderr.is_empty());
        assert_eq!(c.stderr_observed_bytes, 0);
        assert!(c.stdout_observed_bytes <= 5);
        assert_eq!(c.stdout_observed_bytes, bytes.len() as u64);
        assert!(!c.stdout_truncated && !c.stderr_truncated && !c.observed_bytes_overflowed);
        if eof {
            if c.stdout_eof && c.stderr_eof {
                assert_eq!(bytes.as_slice(), b"ready");
                break;
            }
        } else {
            assert!(!c.stdout_eof && !c.stderr_eof);
            assert_eq!(child.child.try_wait().unwrap(), None);
            if bytes.as_slice() == b"ready" {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
pub(super) fn proven(store: &crate::store::StoreTransaction, a: &Area) {
    let id = a.identity();
    assert_eq!(
        store
            .local_command_cancellation_stop_evidence(id.taskrun_id, id.attempt_id)
            .unwrap(),
        LocalCommandCancellationStopEvidence::Proven
    );
}
pub(super) fn cancel(
    f: &Fixture,
    a: &Area,
    root: &Path,
) -> (String, String, u64, u64, Vec<Vec<u8>>, receipts::Rows) {
    let (version, prefix) = observations::stream(&f.store, a, TaskRunState::Running);
    let command = fixture::command_id();
    let key = format!("g3-cancel-{}", a.context.run);
    let context = ApplicationCommandContext {
        command_id: command,
        idempotency_key: fixture::key(&key),
        principal_id: PrincipalId(f.principal.as_str().into()),
        actor: Actor::new("capture-test").unwrap(),
    };
    let outcome = TaskRunService::new(
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
        f.scope.runtime_authority_id.clone(),
    )
    .cancel_task_run(
        &context,
        CancelTaskRunInput {
            taskrun_id: a.identity().taskrun_id,
            expected_version: version,
        },
    )
    .unwrap();
    let CommandOutcome::TaskRunCancellationRequested {
        taskrun_id,
        new_version,
    } = outcome
    else {
        panic!("actual public cancellation outcome")
    };
    assert_eq!(taskrun_id, a.identity().taskrun_id);
    assert_eq!(new_version, version + 1);
    let stream = observations::stream(&f.store, a, TaskRunState::Cancelling);
    assert_eq!(stream.0, new_version);
    assert_eq!(stream.1.len(), prefix.len() + 1);
    assert_eq!(&stream.1[..prefix.len()], prefix.as_slice());
    let loaded = f.store.load_task_run(taskrun_id).unwrap();
    assert!(matches!(
        loaded.events.last().unwrap().payload(),
        TaskRunEvent::CancellationRequested
    ));
    let event = loaded.events.last().unwrap();
    assert_eq!(event.command_id(), &command);
    assert_eq!(event.idempotency_key(), &context.idempotency_key);
    proven(&f.store, a);
    let reader = observations::reader(root, a);
    let rows = receipts::observe(&reader, a, stream.1.last().unwrap(), stream.0, None);
    records::absent(root, a);
    (command.to_string(), key, version, stream.0, stream.1, rows)
}
