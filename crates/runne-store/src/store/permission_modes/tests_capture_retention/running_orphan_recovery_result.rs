//! Physical branches stay distinct; empty-at-entry is never strict live-orphan evidence.
use super::{
    attempt::Attempt,
    context::CaseContext,
    metadata::Area,
    records::{self, Cut},
    recovery_receipts::Receipts,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum Branch {
    RunningAtCrashAlreadyEmpty,
    LiveAtEntryEmptyBeforeStop,
    LiveOrphanStop,
}
impl Branch {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::RunningAtCrashAlreadyEmpty => "RUNNING_AT_CRASH_ALREADY_EMPTY",
            Self::LiveAtEntryEmptyBeforeStop => "LIVE_AT_ENTRY_EMPTY_BEFORE_STOP",
            Self::LiveOrphanStop => "LIVE_ORPHAN_STOP",
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultRecord {
    pub original_digest: String,
    pub cut_digest: String,
    pub ack_digest: String,
    pub after_ack_digest: String,
    pub recovery_pid: u32,
    pub epoch: u64,
    pub next_epoch: u64,
    pub branch: Branch,
    pub barrier: Option<Attempt>,
    pub settled_attempt: Attempt,
    pub receipts: Receipts,
    pub version: u64,
    pub events: Vec<Vec<u8>>,
    pub replay_same_epoch: bool,
    pub replay_newer_epoch: bool,
    pub removed: bool,
}
impl ResultRecord {
    pub(super) fn validate(
        &self,
        context: &CaseContext,
        area: &Area,
        cut: &Cut,
        original_digest: &str,
        cut_digest: &str,
        ack_digest: &str,
        after_ack_digest: &str,
    ) {
        area.validate(context);
        for (actual, expected) in [
            (&self.original_digest, original_digest),
            (&self.cut_digest, cut_digest),
            (&self.ack_digest, ack_digest),
            (&self.after_ack_digest, after_ack_digest),
        ] {
            records::digest(expected);
            assert_eq!(actual, expected);
        }
        super::model::pid(self.recovery_pid);
        assert!(
            ![
                area.writer_pid,
                context.record.collector,
                context.record.supervisor,
                cut.live.association.native
            ]
            .contains(&self.recovery_pid)
        );
        assert!(self.epoch > area.epoch && self.next_epoch > self.epoch);
        match self.branch {
            Branch::RunningAtCrashAlreadyEmpty => assert!(self.barrier.is_none()),
            Branch::LiveAtEntryEmptyBeforeStop | Branch::LiveOrphanStop => {
                let barrier = self.barrier.as_ref().unwrap();
                barrier.validate(area, "stop_unconfirmed");
                barrier.same_immutable(&cut.durable.attempt);
            }
        }
        self.settled_attempt.validate(area, "outcome_unknown");
        self.settled_attempt.same_immutable(&cut.durable.attempt);
        assert_eq!(self.version, cut.durable.stream_version + 2);
        assert_eq!(self.events.len(), cut.durable.event_ids.len() + 2);
        assert_eq!(
            &self.events[..cut.durable.event_ids.len()],
            cut.durable.event_ids.as_slice()
        );
        assert!(self.replay_same_epoch && self.replay_newer_epoch && self.removed);
    }
}
