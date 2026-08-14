//! Replay HTTP handlers — canonical replay session API.
//!
//! Six POST endpoints implement the ADR-0013 replay session lifecycle:
//! open-session, read-page, acknowledge, complete-catch-up, continue-live, close.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, Extension, Path, State, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use gocode_api::{
    ApiReplayBindingId, ApiReplayBindingV1, ApiReplayEventSchema, CanonicalReplayPayloadV1,
    RetentionManifest as ApiRetentionManifest,
};
use gocode_application::local_session::AuthenticatedRuntimeSession;
use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_application::replay_service::{
    ReplayDeliveryPrecommitGuard, ReplayError, ReplayEvent, ReplayService, ReplaySession,
};
use gocode_domain::replay::{ReplayCursor, ReplayScope};
use gocode_store::codec::{ConversationEventCodec, StoreCodec, TaskRunEventCodec};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::auth::AuthenticatedPrincipal;
use crate::error::{RequestId, canonical_error_response};
use crate::limits::{
    LimitsConfig, MAX_ENCODED_REPLAY_PAGE_BYTES, MAX_LIVE_QUEUE_FRAMES, MAX_REPLAY_BODY_BYTES,
    MAX_REPLAY_PAGE_SIZE, ReplayCountPermit, ReplayQuotaManager,
};
use crate::sse::{
    SseDelivery, SseItem, SseSendError, SseSender, SseTerminalFrame, into_sse_stream,
    sse_channel_with_quota,
};

const MAX_CURSOR_TOKEN_BYTES: usize = 8 * 1024;
const MAX_REPLAY_RESUME_BASELINE_BYTES: usize = 1024 * 1024;
pub const REPLAY_BASELINE_RESUME_V2_CAPABILITY: &str =
    "replay.aggregate.retention_baseline_resume.v2";
const CURSOR_TOKEN_PREFIX: &str = "gocode-replay-cursor-v1.";
const MAX_SSE_FRAME_BYTES: usize = 256 * 1024;
const LIVE_POLL_INTERVAL: Duration = Duration::from_millis(25);
const SSE_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);

include!("replay/types.rs");
include!("replay/resume_lease.rs");
include!("replay/retention_baseline_wire.rs");
include!("replay/retention_baseline_v2_wire.rs");
include!("replay/wire_binding.rs");
include!("replay/wire_support.rs");
include!("replay/errors.rs");
include!("replay/handlers.rs");
include!("replay/bounded_response.rs");
include!("replay/resume_v2.rs");
include!("replay/resume_v2_types.rs");
include!("replay/resume_v2_admission.rs");
include!("replay/resume_v2_json.rs");
include!("replay/live_support.rs");
include!("replay/live_producer.rs");
include!("replay/live_stream.rs");
include!("replay/router.rs");

#[cfg(test)]
mod tests {
    include!("replay/tests.rs");
}
