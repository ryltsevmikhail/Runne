//! Desktop implementations of native capability ports.

mod protected_runtime;
mod root_handle_broker;

pub use gocode_api::WorkspaceId;
pub use gocode_api::{PROTECTED_BUNDLED_SESSION_RENEW_AFTER, RootHandleAdmission};
#[cfg(feature = "test-support")]
pub use protected_runtime::FirstActivationFaultPoint;
pub use protected_runtime::{
    DevelopmentBundledRuntimeLauncher, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeLaunchSpec, ProtectedBundledRuntimeProcess,
    ProtectedBundledRuntimeSupervisor, discover_bundled_runtime,
};
#[cfg(all(unix, feature = "protected-channel-integration"))]
pub use root_handle_broker::ProtectedRootHandleEndpoint;
#[cfg(feature = "test-support")]
pub use root_handle_broker::test_transfer_pair;
pub use root_handle_broker::{
    RootHandleBrokerError, RootHandleTransferBinding, RootHandleTransferReceiver,
    RootHandleTransferSender, VerifiedRootHandle,
};
#[cfg(all(unix, feature = "test-support"))]
pub use root_handle_broker::{test_transfer_receiver, test_transfer_sender};

use std::collections::VecDeque;
use std::fmt;
use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use thiserror::Error;

const MINIMUM_WINDOW_WIDTH: i32 = 960;
const MINIMUM_WINDOW_HEIGHT: i32 = 600;
const DEFAULT_WINDOW_WIDTH: i32 = 1_440;
const DEFAULT_WINDOW_HEIGHT: i32 = 900;
const BACKOFF_DELAYS: [Duration; 5] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
const UNEXPECTED_EXIT_WINDOW: Duration = Duration::from_mins(10);

include!("desktop_types.rs");
include!("desktop_supervisor.rs");
include!("desktop_support.rs");

#[cfg(test)]
mod tests {
    include!("tests/support.rs");
    include!("tests/supervisor.rs");
    include!("tests/recovery.rs");
    include!("tests/backoff_and_geometry.rs");
}
