use super::command::{decode_terminal_result, encode_terminal_result};
use super::loop_refs::*;
use super::primitives::*;
use super::refs::*;
use super::*;

/// Codec for [`TaskRunEvent`] payload BLOB.
pub struct TaskRunEventCodec;

impl StoreCodec<TaskRunEvent> for TaskRunEventCodec {
    const CODEC_VERSION: u16 = 1;

    fn encode(&self, value: &TaskRunEvent) -> Result<Vec<u8>, StoreCodecError> {
        include!("task_run/encode_body.rs")
    }

    fn decode(&self, bytes: &[u8]) -> Result<TaskRunEvent, StoreCodecError> {
        include!("task_run/decode_body.rs")
    }
}
