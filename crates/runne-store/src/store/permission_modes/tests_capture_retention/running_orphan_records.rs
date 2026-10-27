//! Typed predecessor-bound observations; data does not grant native authority.
use super::{
    association::Association,
    context::CaseContext,
    live::{LiveSample, READY},
    metadata::{Area, Kind},
    snapshot::Running,
};
use serde::{Deserialize, Serialize};

pub(super) fn digest(value: &str) {
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}

fn association(value: &Association, area: &Area) {
    assert_eq!(value.spawner.writer, area.writer_pid);
    super::model::pid(value.spawner.tid);
    super::model::pid(value.native);
    assert_ne!(value.native, area.writer_pid);
    assert_ne!(value.native, area.context.collector);
    assert_ne!(value.native, area.context.supervisor);
    assert!(value.start_ticks > 0);
    assert_eq!(value.nspid, [value.native, 1]);
    assert!(value.membership.starts_with('/'));
    assert_eq!(
        super::association::membership(&format!("0::{}\n", value.membership)),
        value.membership
    );
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BeforeGo {
    pub original_digest: String,
    pub association: Association,
}
impl BeforeGo {
    pub(super) fn validate(&self, area: &Area, original_digest: &str) {
        digest(original_digest);
        assert_eq!(self.original_digest, original_digest);
        association(&self.association, area);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AfterReady {
    pub before_go_digest: String,
    pub live: LiveSample,
}
impl AfterReady {
    pub(super) fn validate(&self, before: &BeforeGo, predecessor: &str) {
        digest(predecessor);
        assert_eq!(self.before_go_digest, predecessor);
        assert_eq!(self.live.association, before.association);
        assert_eq!(self.live.output.stdout, READY);
        assert_eq!(self.live.output.stdout_observed, READY.len() as u64);
        assert_eq!(self.live.output.stderr_observed, 0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Cut {
    pub after_ready_digest: String,
    pub control_digest: String,
    pub live: LiveSample,
    pub durable: Running,
}
impl Cut {
    pub(super) fn validate(
        &self,
        context: &CaseContext,
        area: &Area,
        ready: &AfterReady,
        ready_digest: &str,
        control_digest: &str,
    ) {
        area.validate(context);
        assert_eq!(area.kind, Kind::Original);
        digest(ready_digest);
        digest(control_digest);
        assert_eq!(self.after_ready_digest, ready_digest);
        assert_eq!(self.control_digest, control_digest);
        assert_eq!(self.live, ready.live);
        self.durable.validate(area);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Ack {
    pub cut_digest: String,
    pub supervisor_pid: u32,
    pub association: Association,
    pub durable: Running,
}
impl Ack {
    pub(super) fn validate(&self, context: &CaseContext, cut: &Cut, cut_digest: &str) {
        digest(cut_digest);
        assert_eq!(self.cut_digest, cut_digest);
        assert_eq!(self.supervisor_pid, context.record.supervisor);
        assert_eq!(self.association, cut.live.association);
        assert_eq!(self.durable, cut.durable);
    }
}
