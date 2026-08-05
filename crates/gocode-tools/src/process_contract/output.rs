//! Source-bounded transient process output capture contracts.

mod output_collector;
mod output_payload;
mod output_types;

#[cfg(test)]
mod tests;

pub(crate) use output_collector::ProcessOutputCollectorV1;
pub(crate) use output_payload::{
    ProcessCapturedOutputV1, ProcessOutputCallerIdV1, TransientProcessOutputChannelV1,
};
pub use output_payload::{ProcessOutputChannelEvidenceV1, ProcessOutputEvidenceV1};
pub use output_types::{
    ProcessCancellationDispositionV1, ProcessOutputBoundsV1, ProcessOutputCaptureErrorV1,
    ProcessOutputSourceErrorV1, ProcessOutputSourceViolationV1, ProcessOutputStopEvidenceV1,
};
pub(crate) use output_types::{
    ProcessOutputReadBudgetV1, ProcessOutputSourceEventV1, ProcessOutputSourcePortV1,
    ProcessOutputStopReasonV1, ProcessOutputStreamV1,
};
