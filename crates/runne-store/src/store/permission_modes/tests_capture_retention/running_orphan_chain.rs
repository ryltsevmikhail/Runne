//! Each predecessor digest is computed independently from authenticated helper bytes.
use super::{
    after_ack::AfterAck,
    context::CaseContext,
    control_result,
    helper_failure::require,
    metadata::Area,
    record_protocol::Name,
    record_publication,
    records::{Ack, AfterReady, BeforeGo, Cut},
};

pub(super) struct Chain {
    pub control: control_result::ResultRecord,
    pub control_digest: String,
    pub area: Area,
    pub original_digest: String,
    pub before: BeforeGo,
    pub ready: AfterReady,
    pub cut: Cut,
    pub cut_digest: String,
}
pub(super) fn read(context: &CaseContext) -> Chain {
    let (control, control_digest): (control_result::ResultRecord, String) =
        require(record_publication::read(context, Name::ControlResult));
    control.validate(context);
    let (area, original_digest): (Area, String) =
        require(record_publication::read(context, Name::OriginalArea));
    area.validate(context);
    control.distinct(&area, &control_digest);
    let (before, before_digest): (BeforeGo, String) =
        require(record_publication::read(context, Name::BeforeGo));
    before.validate(&area, &original_digest);
    let (ready, ready_digest): (AfterReady, String) =
        require(record_publication::read(context, Name::AfterReady));
    ready.validate(&before, &before_digest);
    let (cut, cut_digest): (Cut, String) =
        require(record_publication::read(context, Name::RunningCut));
    cut.validate(context, &area, &ready, &ready_digest, &control_digest);
    Chain {
        control,
        control_digest,
        area,
        original_digest,
        before,
        ready,
        cut,
        cut_digest,
    }
}
pub(super) fn acknowledged(
    context: &CaseContext,
    chain: &Chain,
) -> (Ack, String, AfterAck, String) {
    let (ack, ack_digest): (Ack, String) =
        require(record_publication::read(context, Name::SupervisorAck));
    ack.validate(context, &chain.cut, &chain.cut_digest);
    let (after, after_digest): (AfterAck, String) =
        require(record_publication::read(context, Name::AfterAck));
    after.validate(context, &ack, &ack_digest, &chain.cut);
    (ack, ack_digest, after, after_digest)
}
