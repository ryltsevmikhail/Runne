//! Runtime transport and schema bundle verification.
//!
//! The canonical schema bundle (`gocode-ui-client/1`) is generated
//! byte-for-byte by the runtime contract generator. This module verifies the
//! exact content-only bundle digest independently from release source evidence.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;

mod canonical;
mod local_profile;
mod local_session;
mod replay;
mod sse;

pub use canonical::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, ConversationCreated,
    ConversationMessage, ConversationMessageRole, ConversationMessages, ConversationTextResult,
    CreateConversationRequest, GenerateTextRequest, REQUIRED_RUNTIME_CAPABILITIES, RuntimeApiError,
    RuntimeApiErrorKind, RuntimeSessionAuthority, RuntimeSessionInfo, RuntimeTransportKind,
};
pub use local_profile::{
    LocalProfileError, LocalRuntimeConnectError, LocalRuntimeProfile, default_local_profile_path,
};
pub use local_session::ProtectedBundledRuntimeProfile;
pub use replay::{
    CanonicalReplayEvent, CanonicalReplayPayload, ConversationReplayPayload, LiveDeliveryId,
    ReconnectDecision, ReconnectPolicy, ReconnectRuntime, ReplayAggregateKind, ReplayClientError,
    ReplayClientErrorKind, ReplayCursor, ReplayDelivery, ReplayDeliveryDisposition,
    ReplayIdentityTracker, ReplayLiveSession, ReplayPersistenceBinding, ReplayPersistenceHandoff,
    ReplayRecoveryDisposition, ReplayScope, ReplaySensitivity, ReplaySessionId, ReplayStreamEvent,
    ReplayTerminal, ReplayTerminalCode, TaskRunReplayPayload, replay_persistence_digest,
};
pub use sse::{MAXIMUM_SSE_FRAME_BYTES, SSE_SILENCE_TIMEOUT};

include!("lib_parts/mock_transport.rs");
include!("lib_parts/transport.rs");
include!("lib_parts/health.rs");

#[cfg(test)]
mod tests {
    include!("lib_parts/tests.rs");
}
