//! Platform-neutral application orchestration.

use std::collections::{HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use gocode_local_store::{
    LocalStore, ProjectOpenError, RecentRoot, RecentRootError, ReplayScopeKey,
    SecurityTransactionError, StoreOpenError,
};
use gocode_runtime_client::{
    AuthenticatedRuntimeClient, CanonicalId, CommandIdentity, CreateConversationRequest,
    GenerateTextRequest, LocalProfileError, LocalRuntimeConnectError, LocalRuntimeProfile,
    ReconnectDecision, ReconnectPolicy, ReplayAggregateKind, ReplayClientError,
    ReplayIdentityTracker, ReplayRecoveryDisposition, ReplayScope, ReplayStreamEvent,
    RuntimeApiErrorKind, RuntimeOperationalTelemetrySnapshotV1, RuntimeTransportKind,
    TelemetryCompletenessV1, TelemetryFreshnessV1, TelemetrySectionMetaV1,
    default_local_profile_path,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

mod replay;

const RUNTIME_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONVERSATION_REFERENCE_SCHEMA_VERSION: u32 = 2;

include!("lib_parts/errors.rs");
include!("lib_parts/runtime.rs");
include!("lib_parts/snapshots.rs");
include!("lib_parts/core.rs");
include!("lib_parts/open.rs");
include!("lib_parts/bundled.rs");
include!("lib_parts/connect.rs");
include!("lib_parts/subscribe.rs");
include!("lib_parts/projects.rs");
include!("lib_parts/runtime_state.rs");
include!("lib_parts/operational_telemetry.rs");
include!("lib_parts/operational_telemetry_events.rs");
include!("lib_parts/operational_telemetry_state.rs");
include!("lib_parts/operational_telemetry_snapshot.rs");
include!("lib_parts/conversation.rs");
include!("lib_parts/reference.rs");
include!("lib_parts/bootstrap.rs");

#[cfg(test)]
mod tests {
    include!("lib_parts/tests.rs");
    include!("lib_parts/operational_telemetry_tests.rs");
}
