//! Protected inherited-channel admission for bundled daemon launches.

#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LOCAL_RUNTIME_SESSION_TTL, LaunchAuthorityError,
    LaunchAuthorityValidationV1, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedLaunchRequestV2, ProtectedOwnedLaunchV1, ProtectedOwnedLaunchV2,
    ProtectedRenewRequestV1, ProtectedRenewRequestV2, ProtectedRenewTicketV1,
    ProtectedRenewTicketV2, ProtectedRuntimeProfileV1, ProtectedShutdownAckV1,
    ProtectedShutdownAckV2, ProtectedShutdownV1, ProtectedShutdownV2, ProviderActivationModeV1,
    RuntimeSessionBinding, StableRuntimeBindingV1,
};
#[cfg(unix)]
use gocode_application::local_session::LocalSessionService;
#[cfg(unix)]
use gocode_store::schema;
#[cfg(unix)]
use rand::{RngCore, rngs::OsRng};
#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use zeroize::{Zeroize, Zeroizing};

#[cfg(unix)]
use crate::bootstrap::{
    BootstrapOutcome, bootstrap_protected, preflight_recoverable_first_activation_sidecars,
};
#[cfg(unix)]
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
#[cfg(unix)]
use crate::provider_activation::ProviderActivation;

#[cfg(unix)]
const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
#[cfg(unix)]
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(unix)]
const CONTROL_IDLE_TIMEOUT: Duration =
    Duration::from_secs(LOCAL_RUNTIME_SESSION_TTL.as_secs() + CHANNEL_TIMEOUT.as_secs());
#[cfg(unix)]
const LOCAL_PRINCIPAL: &str = "local-owner";

#[cfg(unix)]
mod channel;
#[cfg(unix)]
mod control;
#[cfg(unix)]
mod first_activation;
#[cfg(unix)]
mod launch;
#[cfg(unix)]
mod request;

#[cfg(unix)]
pub use channel::ProtectedActivationChannel;
#[cfg(unix)]
pub use control::{run_control_loop, run_control_loop_v2};
#[cfg(unix)]
pub use first_activation::random_control_secret;
#[cfg(unix)]
pub use launch::{ProtectedDaemonLaunch, VerifiedProtectedApplicationStart};

#[cfg(not(unix))]
pub struct ProtectedActivationChannel;

#[cfg(not(unix))]
impl ProtectedActivationChannel {
    pub fn from_inherited_stdin() -> Result<Option<Self>, gocode_api::LaunchAuthorityError> {
        Ok(None)
    }
}
