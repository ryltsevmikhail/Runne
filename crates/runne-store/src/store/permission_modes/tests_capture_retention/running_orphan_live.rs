//! Actual unreaped native ownership stays with the caller throughout every sample.
use super::association::{Association, Spawner};
use super::context::CaseContext;
use super::held_area::HeldAreaReader;
use runne_platform::local_command_linux::{LinuxCommandOutputChunkV1, PermissionChildV1};
use serde::{Deserialize, Serialize};

pub(super) const READY: &[u8] = b"ready\n";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Output {
    pub stdout: Vec<u8>,
    pub stdout_observed: u64,
    pub stderr_observed: u64,
}

#[derive(Default)]
pub(super) struct OutputTracker {
    stdout: Vec<u8>,
    last_stdout: u64,
}

impl OutputTracker {
    // take_output returns new bytes but lifetime counters. Never reset the tracker.
    fn append(&mut self, chunk: LinuxCommandOutputChunkV1) -> bool {
        assert!(!chunk.stdout_eof && !chunk.stderr_eof);
        assert!(!chunk.stdout_truncated && !chunk.stderr_truncated);
        assert!(!chunk.observed_bytes_overflowed);
        assert_eq!(chunk.leader_exit_code, None);
        assert!(chunk.stderr.is_empty());
        assert_eq!(chunk.stderr_observed_bytes, 0);
        assert!(chunk.stdout_observed_bytes >= self.last_stdout);
        assert_eq!(
            chunk.stdout_observed_bytes - self.last_stdout,
            u64::try_from(chunk.stdout.len()).unwrap()
        );
        assert!(self.stdout.len() + chunk.stdout.len() <= READY.len());
        self.stdout.extend_from_slice(&chunk.stdout);
        assert!(READY.starts_with(&self.stdout));
        self.last_stdout = chunk.stdout_observed_bytes;
        assert_eq!(self.last_stdout, u64::try_from(self.stdout.len()).unwrap());
        self.stdout == READY
    }

    pub(super) fn poll(&mut self, child: &mut PermissionChildV1<'_>) -> bool {
        assert!(child.was_released());
        assert_eq!(
            child.try_wait().unwrap(),
            None,
            "native must remain unreaped/live"
        );
        child.poll_output().unwrap();
        let ready = self.append(child.take_output());
        assert_eq!(child.try_wait().unwrap(), None);
        ready
    }

    fn snapshot(&self) -> Output {
        assert_eq!(self.stdout, READY);
        assert_eq!(self.last_stdout, READY.len() as u64);
        Output {
            stdout: self.stdout.clone(),
            stdout_observed: self.last_stdout,
            stderr_observed: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LiveSample {
    pub association: Association,
    pub output: Output,
}

// No helper launch, GO, stop, reap, terminal evidence, record or marker write here.
// A later sample must supply the previous association to establish continuity.
pub(super) fn sample(
    context: &CaseContext,
    held: &HeldAreaReader,
    spawner: &Spawner,
    native: u32,
    outer_pids: &[u32],
    child: &mut PermissionChildV1<'_>,
    tracker: &mut OutputTracker,
    previous: &Association,
) -> LiveSample {
    context.check_roots();
    let first = held.live_association(context, spawner, native, outer_pids);
    assert_eq!(&first, previous);
    assert!(tracker.poll(child), "ready must already have been observed");
    let second = held.live_association(context, spawner, native, outer_pids);
    assert_eq!(second, first);
    assert!(child.was_released());
    assert_eq!(child.try_wait().unwrap(), None);
    context.deadline.check();
    LiveSample {
        association: second,
        output: tracker.snapshot(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn chunk(bytes: &[u8], total: u64) -> LinuxCommandOutputChunkV1 {
        LinuxCommandOutputChunkV1 {
            stdout: bytes.to_vec(),
            stdout_observed_bytes: total,
            ..Default::default()
        }
    }
    #[test]
    fn split_ready_and_repeated_empty_poll_preserve_lifetime_counter() {
        let mut tracker = OutputTracker::default();
        assert!(!tracker.append(chunk(b"rea", 3)));
        assert!(tracker.append(chunk(b"dy\n", 6)));
        assert!(tracker.append(chunk(b"", 6)));
        assert_eq!(tracker.snapshot().stdout, READY);
    }
    #[test]
    fn exit_eof_flood_counter_reset_and_extra_bytes_cannot_be_live_ready() {
        let mut cases = vec![
            chunk(b"ready\nextra", 11),
            chunk(b"wrong\n", 6),
            chunk(b"", 1),
        ];
        let mut eof = chunk(b"ready\n", 6);
        eof.stdout_eof = true;
        cases.push(eof);
        let mut err = chunk(b"ready\n", 6);
        err.stderr_observed_bytes = 1;
        cases.push(err);
        let mut exit = chunk(b"ready\n", 6);
        exit.leader_exit_code = Some(0);
        cases.push(exit);
        let mut flood = chunk(b"ready\n", 6);
        flood.stdout_truncated = true;
        cases.push(flood);
        let mut overflow = chunk(b"ready\n", 6);
        overflow.observed_bytes_overflowed = true;
        cases.push(overflow);
        for value in cases {
            assert!(std::panic::catch_unwind(|| OutputTracker::default().append(value)).is_err());
        }
        let mut tracker = OutputTracker::default();
        tracker.append(chunk(READY, 6));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                || tracker.append(chunk(b"", 0))
            ))
            .is_err()
        );
    }
}
