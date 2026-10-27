//! Separate real cancellation control. Serialized claims require actual caller witnesses.
use super::{
    cancel::Requested,
    context::CaseContext,
    control_receipts::{self, Rows},
    live::LiveSample,
    metadata::{Area, Kind},
    native::Exit,
    records,
    snapshot::Running,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ResultRecord {
    pub original: Area,
    pub live: LiveSample,
    pub before: Running,
    pub requested: Requested,
    pub receipts: Rows,
    pub exit: Exit,
    pub reaped: bool,
    pub eof: bool,
    pub empty: bool,
    pub removed: bool,
}

impl ResultRecord {
    pub(super) fn validate(&self, context: &CaseContext) {
        self.original.validate(context);
        assert_eq!(self.original.kind, Kind::Control);
        self.before.validate(&self.original);
        assert_eq!(
            self.live.association.spawner.writer,
            context.record.supervisor
        );
        assert_eq!(self.live.output.stdout, super::live::READY);
        assert_eq!(
            self.live.output.stdout_observed,
            super::live::READY.len() as u64
        );
        assert_eq!(self.live.output.stderr_observed, 0);
        let command: runne_domain::id::CommandId = self.requested.command.parse().unwrap();
        assert_eq!(command.to_string(), self.requested.command);
        assert_eq!(
            self.requested.key,
            format!("r05-running-control-{}", context.record.scenario)
        );
        assert_eq!(self.requested.expected_version, self.before.stream_version);
        assert_eq!(self.requested.version, self.before.stream_version + 1);
        assert_eq!(self.requested.events.len(), self.before.event_ids.len() + 1);
        assert_eq!(
            &self.requested.events[..self.before.event_ids.len()],
            self.before.event_ids.as_slice()
        );
        let head = self.requested.events.last().unwrap();
        control_receipts::validate_stop(
            &self.receipts.stop,
            &self.original,
            head,
            self.requested.version,
        );
        control_receipts::validate_occupation(&self.receipts.occupation, &self.original, None);
        assert_eq!(self.receipts.terminal, None);
        assert!(self.reaped && self.eof && self.empty && self.removed);
        if let Exit::Signaled { signal, .. } = self.exit {
            assert!((1..=64).contains(&signal));
        }
    }
    pub(super) fn distinct(&self, original: &Area, digest: &str) {
        records::digest(digest);
        assert_ne!(self.original.nested, original.nested);
        assert_ne!(self.original.authority, original.authority);
        assert_ne!(self.original.capture.task, original.capture.task);
        assert_ne!(self.original.area, original.area);
        assert_ne!(self.original.capture.owner, original.capture.owner);
        assert_eq!(original.kind, Kind::Original);
    }
}
