//! Optional published after-ACK checkpoint is not the final helper-free abort assertion.
use super::{
    context::CaseContext,
    live::LiveSample,
    records::{self, Ack, Cut},
    snapshot::Running,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AfterAck {
    pub ack_digest: String,
    pub live: LiveSample,
    pub durable: Running,
}
impl AfterAck {
    pub(super) fn validate(&self, context: &CaseContext, ack: &Ack, ack_digest: &str, cut: &Cut) {
        context.check_roots();
        records::digest(ack_digest);
        assert_eq!(self.ack_digest, ack_digest);
        assert_eq!(self.live, cut.live);
        assert_eq!(self.live.association, ack.association);
        assert_eq!(self.durable, ack.durable);
        assert_eq!(self.durable, cut.durable);
    }
}
