//! Strict Aggregate replay protocol, validated delivery identity and recovery.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reqwest::header::{ACCEPT, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::canonical::{AuthenticatedRuntimeClient, CanonicalId};
use crate::sse::{RawSseFrame, SSE_SILENCE_TIMEOUT, SseDecodeError, SseDecoder};

const MAXIMUM_REPLAY_REQUEST_BYTES: usize = 8 * 1024;
const MAXIMUM_REPLAY_RESPONSE_BYTES: usize = 1024 * 1024;
const MAXIMUM_ERROR_RESPONSE_BYTES: usize = 1024 * 1024;
const MAXIMUM_CURSOR_BYTES: usize = 8 * 1024;
const MAXIMUM_EVENT_TYPE_BYTES: usize = 128;
const MAXIMUM_TEXT_BYTES: usize = 64 * 1024;
const MAXIMUM_REASON_BYTES: usize = 4 * 1024;
const REPLAY_PAGE_LIMIT: usize = 256;
const MAXIMUM_TRACKED_IDENTITIES: usize = 512;
const CURSOR_PREFIX: &str = "runne-replay-cursor-v1.";
const LIVE_RESET_INTERVAL: Duration = Duration::from_secs(30);

const RECONNECT_DELAYS: [Duration; 10] = [
    Duration::from_millis(250),
    Duration::from_millis(500),
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
    Duration::from_secs(5),
];

mod accepted_v2_client;
mod baseline;
#[cfg(test)]
mod baseline_tamper_tests;
#[cfg(test)]
mod baseline_tests;
mod client;
mod client_open;
mod http;
mod http_retention;
mod identity;
mod policy;
mod resume;
mod session;
mod strict_json;
#[cfg(test)]
mod tests;
mod types;
mod validation;
mod wire;

pub use accepted_v2_client::ParsedAcceptedPromotionV2;
pub use accepted_v2_client::ReplayAcceptedPromotionV2;
pub use baseline::{
    ReplayBaselineVerificationError, ReplayRetentionBaselineV1, ReplayRetentionBaselineV2,
};
pub use identity::ReplayIdentityTracker;
pub use policy::{
    ReconnectDecision, ReconnectPolicy, ReconnectRuntime, ReplayClientError, ReplayClientErrorKind,
    ReplayRecoveryDisposition,
};
pub use resume::ReplayPendingBaselineResume;
pub use session::{ReplayLiveSession, ReplayStreamEvent, ReplayTerminal, ReplayTerminalCode};
pub use types::{
    CanonicalReplayEvent, CanonicalReplayPayload, ConversationReplayPayload, LiveDeliveryId,
    ReplayAggregateKind, ReplayCursor, ReplayDelivery, ReplayDeliveryDisposition,
    ReplayPersistenceBinding, ReplayPersistenceHandoff, ReplayScope, ReplaySensitivity,
    ReplaySessionId, TaskRunReplayPayload, replay_persistence_digest,
};
