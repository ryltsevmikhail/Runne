use super::command::{decode_terminal_result, encode_terminal_result};
use super::loop_refs::*;
use super::primitives::*;
use super::refs::*;
use super::*;

const TAG_TASK_RUN_SUBMITTED: u8 = 0x22;

mod submitted;

/// Codec for [`TaskRunEvent`] payload BLOB.
pub struct TaskRunEventCodec;

impl StoreCodec<TaskRunEvent> for TaskRunEventCodec {
    const CODEC_VERSION: u16 = 6;

    fn encode(&self, value: &TaskRunEvent) -> Result<Vec<u8>, StoreCodecError> {
        include!("task_run/encode_body.rs")
    }

    fn decode(&self, bytes: &[u8]) -> Result<TaskRunEvent, StoreCodecError> {
        include!("task_run/decode_body.rs")
    }
}
