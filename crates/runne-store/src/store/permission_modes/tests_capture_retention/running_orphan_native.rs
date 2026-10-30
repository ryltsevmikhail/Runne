//! Own the real native handle. Proc association never creates a replacement child.
use super::{
    association::{Association, Spawner},
    clock::Deadline,
    context::CaseContext,
    held_area::HeldAreaReader,
    live::{OutputTracker, READY},
    metadata::Area,
};
use runne_platform::local_command_linux::{LinuxLeaderExitKindV1, PermissionChildV1};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub(super) struct OwnedNative<'a> {
    pub child: PermissionChildV1<'a>,
    pub deadline: Deadline,
    armed: bool,
}
impl<'a> OwnedNative<'a> {
    pub(super) fn new(child: PermissionChildV1<'a>, deadline: Deadline) -> Self {
        Self {
            child,
            deadline,
            armed: true,
        }
    }
}
impl Drop for OwnedNative<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Failure-only best effort; outer collector/init owns ultimate teardown.
        // Intrinsic terminate_area wait is unchanged; no successful-cleanup claim.
        let stop = self.child.terminate_area(Duration::from_millis(20));
        let reap = self
            .deadline
            .try_remaining()
            .map(|left| self.child.reap_after_stop(left));
        eprintln!("R05_RUNNING_FAILURE_NATIVE stop={stop:?} reap={reap:?}");
    }
}

pub(super) fn bind(child: &PermissionChildV1<'_>, saved: &Area) {
    assert_eq!(child.area_identity().as_slice(), saved.area);
    let original = child.original_binding();
    assert_eq!(original.assignment(), &saved.identity());
    assert_eq!(
        original.invocation_id().to_string(),
        saved.capture.invocation
    );
    assert_eq!(
        original.command_intent_digest().as_bytes(),
        &saved.command_digest
    );
}

pub(super) fn ready(
    context: &CaseContext,
    child: &mut OwnedNative<'_>,
    tracker: &mut OutputTracker,
) {
    loop {
        context.deadline.check();
        if tracker.poll(&mut child.child) {
            break;
        }
        std::thread::sleep(context.deadline.remaining().min(Duration::from_millis(1)));
    }
    context.deadline.check();
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Exit {
    Exited { code: u8 },
    Signaled { signal: i32, core_dumped: bool },
}
impl From<LinuxLeaderExitKindV1> for Exit {
    fn from(value: LinuxLeaderExitKindV1) -> Self {
        match value {
            LinuxLeaderExitKindV1::Exited { code } => Self::Exited { code },
            LinuxLeaderExitKindV1::Signaled {
                signal,
                core_dumped,
            } => Self::Signaled {
                signal,
                core_dumped,
            },
        }
    }
}

pub(super) fn stop_control(
    context: &CaseContext,
    native: &mut OwnedNative<'_>,
    held: &HeldAreaReader,
    spawner: &Spawner,
    pid: u32,
    roster: &[u32],
    previous: &Association,
) -> Exit {
    assert_eq!(
        &held.live_association(context, spawner, pid, roster),
        previous
    );
    assert_eq!(native.child.try_wait().unwrap(), None);
    context.deadline.check();
    native
        .child
        .terminate_area(Duration::from_millis(20))
        .unwrap();
    native
        .child
        .reap_after_stop(context.deadline.remaining())
        .unwrap();
    let exit = native
        .child
        .try_wait()
        .unwrap()
        .expect("actual cached owned waitpid");
    loop {
        context.deadline.check();
        native.child.poll_output().unwrap();
        let c = native.child.take_output();
        assert!(c.stdout.is_empty() && c.stderr.is_empty());
        assert_eq!(
            (c.stdout_observed_bytes, c.stderr_observed_bytes),
            (READY.len() as u64, 0)
        );
        assert!(!c.stdout_truncated && !c.stderr_truncated && !c.observed_bytes_overflowed);
        if c.stdout_eof && c.stderr_eof {
            break;
        }
        std::thread::sleep(context.deadline.remaining().min(Duration::from_millis(1)));
    }
    let terminal = native.child.terminal_evidence().unwrap();
    terminal.revalidate_empty_area().unwrap();
    assert_eq!(terminal.leader_exit_kind(), exit);
    assert!(terminal.output_matches(
        READY,
        b"",
        i64::try_from(READY.len()).unwrap(),
        0,
        false,
        false,
        true,
        true,
        false
    ));
    held.area().prove_empty().unwrap().revalidate().unwrap();
    context.deadline.check();
    native.armed = false; // Only after actual collection/EOF/empty verification.
    exit.into()
}
