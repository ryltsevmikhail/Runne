//! ReplayService — coordination durable replay с cursor-based progress.

use std::sync::Arc;

use async_trait::async_trait;
use gocode_api::CanonicalReplayPayloadV1;
use gocode_domain::conversation::ConversationEvent;
use gocode_domain::event::Sensitivity;
use gocode_domain::id::{
    AggregateId, ConversationId, EventId, EventLogLineageId, IntegrityDigest, TaskRunId,
};
use gocode_domain::replay::{CURSOR_SCHEMA_VERSION, CatchUpCompletion, ReplayCursor, ReplayScope};
use gocode_domain::replay::{GapRangeRef, RetentionManifest};
use gocode_domain::task_run::TaskRunEvent;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;
const MAX_EVENT_TYPE_BYTES: usize = 256;
pub const REPLAY_FRAME_CAPACITY_BYTES: usize = 256 * 1024;
pub const REPLAY_PAGE_CAPACITY_BYTES: usize = 1024 * 1024;
pub const REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES: usize = 32 * 1024;
pub const REPLAY_EVENT_VARIABLE_MAX_BYTES: usize =
    REPLAY_FRAME_CAPACITY_BYTES - REPLAY_ENVELOPE_CURSOR_BINDING_OVERHEAD_BYTES;

include!("replay_service/measurement.rs");
include!("replay_service/types.rs");
include!("replay_service/authorization.rs");
include!("replay_service/store_port.rs");
include!("replay_service/errors.rs");
include!("replay_service/authorized_guard.rs");
include!("replay_service/service_setup.rs");
include!("replay_service/service_cursor.rs");
include!("replay_service/service_open.rs");
include!("replay_service/service_read_ack.rs");
include!("replay_service/service_catch_up.rs");
include!("replay_service/service_live.rs");
include!("replay_service/noop_guard.rs");
