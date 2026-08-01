//! Protected inherited-channel admission for bundled daemon launches.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use gocode_api::{
    ActivationDispositionV1, ExecutableIdentityV1, LaunchAuthorityError,
    LaunchAuthorityValidationV1, PendingFirstActivationV1, ProtectedActivationKeys,
    ProtectedFirstActivationCommitV1, ProtectedFirstActivationPreparedV1, ProtectedLaunchRequestV1,
    ProtectedOwnedLaunchV1, ProtectedRenewRequestV1, ProtectedRenewTicketV1,
    ProtectedRuntimeProfileV1, ProtectedShutdownAckV1, ProtectedShutdownV1, RuntimeSessionBinding,
    StableRuntimeBindingV1,
};
use gocode_application::local_session::LocalSessionService;
use gocode_store::schema;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::bootstrap::{
    BootstrapOutcome, bootstrap_protected, preflight_recoverable_first_activation_sidecars,
};
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};

const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
const LOCAL_PRINCIPAL: &str = "local-owner";

include!("protected_activation_parts/channel.rs");
include!("protected_activation_parts/launch.rs");
include!("protected_activation_parts/preflight.rs");
include!("protected_activation_parts/control_loop.rs");
include!("protected_activation_parts/unsupported.rs");
