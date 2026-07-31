//! Protected inherited-channel admission for bundled daemon launches.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use gocode_application::local_session::LocalSessionService;
use gocode_store::schema;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::bootstrap::{
    BootstrapOutcome, bootstrap_protected, preflight_recoverable_first_activation_sidecars,
};
use crate::config::{BuiltInDefaults, ConfigurationSnapshot};
use crate::provider_activation::ProviderActivation;

const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(30);
const CONTROL_IDLE_TIMEOUT: Duration =
    Duration::from_secs(LOCAL_RUNTIME_SESSION_TTL.as_secs() + CHANNEL_TIMEOUT.as_secs());
const LOCAL_PRINCIPAL: &str = "local-owner";

/// Owned daemon side of the inherited full-duplex activation channel.
#[cfg(unix)]
pub struct ProtectedActivationChannel {
    stream: std::os::unix::net::UnixStream,
}

#[cfg(unix)]
impl ProtectedActivationChannel {
    /// Wraps the inherited child endpoint and installs bounded I/O deadlines.
    pub fn new(stream: std::os::unix::net::UnixStream) -> Result<Self, LaunchAuthorityError> {
        stream
            .set_read_timeout(Some(CHANNEL_TIMEOUT))
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        stream
            .set_write_timeout(Some(CHANNEL_TIMEOUT))
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        Ok(Self { stream })
    }

    /// Duplicates stdin only when it is a Unix-domain socket.
    pub fn from_inherited_stdin() -> Result<Option<Self>, LaunchAuthorityError> {
        use std::os::fd::AsFd as _;

        let owned = rustix::io::dup(std::io::stdin().as_fd())
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        let stream = std::os::unix::net::UnixStream::from(owned);
        match stream.peer_addr() {
            Ok(_) => Self::new(stream).map(Some),
            Err(error)
                if error.raw_os_error() == Some(libc::ENOTSOCK)
                    || error.raw_os_error() == Some(libc::EINVAL) =>
            {
                Ok(None)
            }
            Err(_) => Err(LaunchAuthorityError::ProtectedChannelUnavailable),
        }
    }

    fn read_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        let mut prefix = [0; 4];
        self.stream
            .read_exact(&mut prefix)
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        let payload_length = u32::from_be_bytes(prefix) as usize;
        if payload_length == 0 || payload_length > MAX_FRAME_PAYLOAD_BYTES {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let frame_length = payload_length
            .checked_add(4)
            .ok_or(LaunchAuthorityError::InvalidContract)?;
        let mut frame = vec![0; frame_length];
        frame[..4].copy_from_slice(&prefix);
        self.stream
            .read_exact(&mut frame[4..])
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
        Ok(Zeroizing::new(frame))
    }

    fn write_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        if frame.len() < 5 || frame.len() > MAX_FRAME_PAYLOAD_BYTES + 4 {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        self.stream
            .write_all(frame)
            .and_then(|()| self.stream.flush())
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
    }

    /// Reads the next bounded frame for the post-readiness control loop.
    pub fn read_control_frame(&mut self) -> Result<Zeroizing<Vec<u8>>, LaunchAuthorityError> {
        self.read_frame()
    }

    /// Writes one bounded post-readiness control response.
    pub fn write_control_frame(&mut self, frame: &[u8]) -> Result<(), LaunchAuthorityError> {
        self.write_frame(frame)
    }

    fn enter_control_loop(&self) -> Result<(), LaunchAuthorityError> {
        self.stream
            .set_read_timeout(Some(CONTROL_IDLE_TIMEOUT))
            .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)
    }
}

/// Validated protected launch retained only by the daemon native host.
#[cfg(unix)]
enum DaemonLaunchRequest {
    V1(ProtectedLaunchRequestV1),
    V2(ProtectedLaunchRequestV2),
}

#[cfg(unix)]
impl DaemonLaunchRequest {
    fn decode_frame(frame: &[u8]) -> Result<Self, LaunchAuthorityError> {
        if let Ok(request) = ProtectedLaunchRequestV2::decode_frame(frame) {
            return Ok(Self::V2(request));
        }
        ProtectedLaunchRequestV1::decode_frame(frame)
            .map(Self::V1)
            .map_err(|_| LaunchAuthorityError::InvalidContract)
    }

    const fn compatibility(&self) -> &ProtectedLaunchRequestV1 {
        match self {
            Self::V1(request) => request,
            Self::V2(request) => request.compatibility_request(),
        }
    }

    fn validate(
        &self,
        now_unix_millis: u64,
        expected: &LaunchAuthorityValidationV1<'_>,
    ) -> Result<ProviderActivation, LaunchAuthorityError> {
        match self {
            Self::V1(request) => {
                request.validate(now_unix_millis, expected)?;
                request.validate_provider_mode(ProviderActivationModeV1::DeterministicV1)?;
                Ok(ProviderActivation::deterministic_v1())
            }
            Self::V2(request) => {
                let activation =
                    ProviderActivation::from_binding(request.provider_binding().clone());
                request.validate(now_unix_millis, expected, activation.binding())?;
                Ok(activation)
            }
        }
    }

    fn derive_keys_and_forget(&mut self) -> ProtectedActivationKeys {
        match self {
            Self::V1(request) => request.derive_keys_and_forget(),
            Self::V2(request) => request.derive_keys_and_forget(),
        }
    }

    fn validate_freshness(&self, now_unix_millis: u64) -> Result<(), LaunchAuthorityError> {
        match self {
            Self::V1(request) => request.validate_freshness(now_unix_millis),
            Self::V2(request) => request.validate_freshness(now_unix_millis),
        }
    }
}

/// Validated protected launch retained only by the daemon native host.
#[cfg(unix)]
pub struct ProtectedDaemonLaunch {
    request: DaemonLaunchRequest,
    keys: ProtectedActivationKeys,
    config: ConfigurationSnapshot,
    pending_first_activation: Option<PendingFirstActivationV1>,
    provider_activation: ProviderActivation,
}

#[cfg(unix)]
impl ProtectedDaemonLaunch {
    /// Reads, validates, and—when needed—two-phase commits first activation.
    pub fn accept<F>(
        channel: &mut ProtectedActivationChannel,
        executable_path: &Path,
        mut now_unix_millis: F,
    ) -> Result<Self, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        let frame = channel.read_frame()?;
        let mut request = DaemonLaunchRequest::decode_frame(&frame)?;
        let executable = ExecutableIdentityV1::measure(executable_path)?;
        let profile = expected_profile()?;
        let provider_activation = request.validate(
            now_unix_millis()?,
            &LaunchAuthorityValidationV1 {
                principal_id: LOCAL_PRINCIPAL,
                profile: &profile,
                executable: &executable,
            },
        )?;
        let canonical_root = validate_runtime_root(request.compatibility().runtime_root())?;
        if canonical_root != request.compatibility().runtime_root() {
            return Err(LaunchAuthorityError::InvalidContract);
        }
        let mut defaults = BuiltInDefaults::new(&canonical_root);
        defaults.http_bind = "127.0.0.1:0".to_owned();
        let config = ConfigurationSnapshot::from_defaults(&defaults);
        let keys = request.derive_keys_and_forget();

        let pending_first_activation = match request.compatibility().activation_disposition() {
            ActivationDispositionV1::FirstActivation => {
                if Path::new(&config.db_path).exists() {
                    return Err(LaunchAuthorityError::UnexpectedExistingEventLog);
                }
                let pending = prepare_first_activation(request.compatibility(), &canonical_root)?;
                let mut prepared = ProtectedFirstActivationPreparedV1::new(
                    request.compatibility().launch_authority_id(),
                    request.compatibility().desktop_host_instance_id(),
                    pending.clone(),
                );
                prepared.sign(&keys);
                channel.write_frame(
                    &prepared
                        .encode_frame()
                        .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                )?;
                let commit = ProtectedFirstActivationCommitV1::decode_frame(&channel.read_frame()?)
                    .map_err(|_| LaunchAuthorityError::FirstActivationCommitIncomplete)?;
                commit.verify_exact(request.compatibility(), &pending, &keys)?;
                request.validate_freshness(now_unix_millis()?)?;
                Some(pending)
            }
            ActivationDispositionV1::Existing(expected) => {
                preflight_existing(&config, expected, None)?;
                None
            }
            ActivationDispositionV1::ResumeFirstActivation(pending) => {
                verify_pending_request(request.compatibility(), pending, &canonical_root)?;
                if Path::new(&config.db_path).exists() {
                    preflight_resume_first_activation(&config, pending)?;
                }
                Some(pending.as_ref().clone())
            }
        };

        Ok(Self {
            request,
            keys,
            config,
            pending_first_activation,
            provider_activation,
        })
    }

    /// Completes storage bootstrap only after protected admission succeeded.
    pub fn bootstrap<F>(
        &mut self,
        mut now_unix_millis: F,
    ) -> Result<BootstrapOutcome, LaunchAuthorityError>
    where
        F: FnMut() -> Result<u64, LaunchAuthorityError>,
    {
        self.request.validate_freshness(now_unix_millis()?)?;
        let bootstrap_key = self.keys.bootstrap_key();
        let result = bootstrap_protected(
            &self.config,
            self.request.compatibility().launch_authority_id(),
            *bootstrap_key,
            self.pending_first_activation.as_ref(),
            || {
                let now = now_unix_millis().map_err(|_| {
                    crate::error::DaemonError::Bootstrap(
                        "protected launch authority expired".into(),
                    )
                })?;
                self.request.validate_freshness(now).map_err(|_| {
                    crate::error::DaemonError::Bootstrap(
                        "protected launch authority expired".into(),
                    )
                })
            },
        );
        self.keys.forget_bootstrap_key();
        result.map_err(|error| {
            if error.to_string().contains("already consumed") {
                LaunchAuthorityError::ReusedLaunchAuthority
            } else if error.to_string().contains("expired") {
                LaunchAuthorityError::StaleLaunchAuthority
            } else if error.to_string().contains("prepared") {
                LaunchAuthorityError::FirstActivationPreparationMismatch
            } else {
                LaunchAuthorityError::InvalidContract
            }
        })
    }

    pub const fn request_v1(&self) -> Option<&ProtectedLaunchRequestV1> {
        match &self.request {
            DaemonLaunchRequest::V1(request) => Some(request),
            DaemonLaunchRequest::V2(_) => None,
        }
    }

    /// Returns the read-only V1 compatibility identity used by existing
    /// first-activation recovery code. It never carries or selects a provider.
    pub const fn request(&self) -> &ProtectedLaunchRequestV1 {
        self.request.compatibility()
    }

    pub const fn request_v2(&self) -> Option<&ProtectedLaunchRequestV2> {
        match &self.request {
            DaemonLaunchRequest::V1(_) => None,
            DaemonLaunchRequest::V2(request) => Some(request),
        }
    }

    pub const fn provider_activation(&self) -> &ProviderActivation {
        &self.provider_activation
    }

    pub const fn keys(&self) -> &ProtectedActivationKeys {
        &self.keys
    }

    pub const fn config(&self) -> &ConfigurationSnapshot {
        &self.config
    }
}

fn expected_profile() -> Result<ProtectedRuntimeProfileV1, LaunchAuthorityError> {
    let profile_hash: [u8; 32] = hex::decode(gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::ProfileHashMismatch)?;
    ProtectedRuntimeProfileV1::new(
        "gocode-bundled-runtime/1",
        1,
        gocode_runtime::bundle::BUNDLE_ID,
        profile_hash,
        gocode_http::runtime_profile::ordered_capability_digest(
            gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
        ),
    )
}

fn prepare_first_activation(
    request: &ProtectedLaunchRequestV1,
    runtime_root: &Path,
) -> Result<PendingFirstActivationV1, LaunchAuthorityError> {
    let authority_id = *uuid::Uuid::now_v7().as_bytes();
    let lineage_id = *uuid::Uuid::now_v7().as_bytes();
    let preparation_id = *uuid::Uuid::now_v7().as_bytes();
    let profile = request.profile().clone();
    let stable = StableRuntimeBindingV1::new(
        authority_id,
        request.principal_id(),
        lineage_id,
        profile.profile_id(),
        *profile.profile_hash(),
        *profile.capability_digest(),
    )?;
    PendingFirstActivationV1::new(
        preparation_id,
        runtime_root_identity(runtime_root),
        stable,
        request.executable().clone(),
        profile,
    )
}

fn verify_pending_request(
    request: &ProtectedLaunchRequestV1,
    pending: &PendingFirstActivationV1,
    runtime_root: &Path,
) -> Result<(), LaunchAuthorityError> {
    if pending.runtime_root_identity() != &runtime_root_identity(runtime_root)
        || pending.executable() != request.executable()
        || pending.profile() != request.profile()
        || pending.stable().principal_id() != request.principal_id()
    {
        return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
    }
    Ok(())
}

fn preflight_existing(
    config: &ConfigurationSnapshot,
    expected: &StableRuntimeBindingV1,
    expected_preparation_id: Option<&[u8; 16]>,
) -> Result<(), LaunchAuthorityError> {
    let db_path = Path::new(&config.db_path);
    if !db_path.exists() {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    match schema::open_existing_read_only(db_path) {
        Ok(connection) => {
            validate_existing_connection(config, &connection, expected, expected_preparation_id)
        }
        Err(_) => schema::with_protected_recovery_read_only_admission(db_path, |connection| {
            validate_existing_connection(config, connection, expected, expected_preparation_id)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding),
    }
}

fn validate_existing_connection(
    config: &ConfigurationSnapshot,
    connection: &rusqlite::Connection,
    expected: &StableRuntimeBindingV1,
    expected_preparation_id: Option<&[u8; 16]>,
) -> Result<(), LaunchAuthorityError> {
    let lineage = schema::read_event_log_lineage_id(connection)
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding)?
        .ok_or(LaunchAuthorityError::MissingExpectedStableBinding)?;
    let preparation = schema::read_first_activation_preparation(connection)
        .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
    let local_authority_path =
        Path::new(&config.replay_integrity_key_path).with_file_name("local-session-authority-id");
    let local_authority = read_owner_private_uuid(&local_authority_path)?;
    let expected_profile_hash: [u8; 32] =
        hex::decode(gocode_runtime::bundle::PUBLISHED_BUNDLE_HASH)
            .ok()
            .and_then(|bytes| <Vec<u8> as TryInto<[u8; 32]>>::try_into(bytes).ok())
            .ok_or(LaunchAuthorityError::ProfileHashMismatch)?;
    if local_authority != *expected.authority_id()
        || lineage.as_bytes() != expected.lineage_id()
        || expected.principal_id() != LOCAL_PRINCIPAL
        || expected.profile_id() != gocode_runtime::bundle::BUNDLE_ID
        || expected.profile_hash() != &expected_profile_hash
        || expected.capability_digest()
            != &gocode_http::runtime_profile::ordered_capability_digest(
                gocode_runtime::bundle::PUBLISHED_RUNTIME_CAPABILITIES,
            )
        || expected_preparation_id
            .is_some_and(|expected_id| preparation.as_ref() != Some(expected_id))
    {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    Ok(())
}

fn preflight_resume_first_activation(
    config: &ConfigurationSnapshot,
    pending: &PendingFirstActivationV1,
) -> Result<(), LaunchAuthorityError> {
    let db_path = Path::new(&config.db_path);
    match schema::open_existing_read_only(db_path) {
        Ok(connection) => validate_resume_first_activation_connection(config, &connection, pending),
        Err(_) => schema::with_protected_recovery_read_only_admission(db_path, |connection| {
            validate_resume_first_activation_connection(config, connection, pending)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch),
    }
}

fn validate_resume_first_activation_connection(
    config: &ConfigurationSnapshot,
    connection: &rusqlite::Connection,
    pending: &PendingFirstActivationV1,
) -> Result<(), LaunchAuthorityError> {
    let lineage = uuid::Uuid::from_bytes(*pending.stable().lineage_id())
        .to_string()
        .parse()
        .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?;
    match schema::preflight_first_activation_resume(
        connection,
        pending.stable().authority_id(),
        lineage,
        pending.preparation_id(),
    )
    .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)?
    {
        schema::FirstActivationResumeState::Prepared => validate_existing_connection(
            config,
            connection,
            pending.stable(),
            Some(pending.preparation_id()),
        ),
        schema::FirstActivationResumeState::RecoverablePrepared => {
            preflight_recoverable_first_activation_sidecars(config, pending.stable().authority_id())
                .map_err(|_| LaunchAuthorityError::FirstActivationPreparationMismatch)
        }
        schema::FirstActivationResumeState::RecoverablePartial => {
            let replay_key = Path::new(&config.replay_integrity_key_path);
            let local_authority = replay_key.with_file_name("local-session-authority-id");
            if replay_key.exists() || local_authority.exists() {
                return Err(LaunchAuthorityError::FirstActivationPreparationMismatch);
            }
            Ok(())
        }
    }
}

fn validate_runtime_root(path: &Path) -> Result<PathBuf, LaunchAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchAuthorityError::ProtectedChannelUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(LaunchAuthorityError::InvalidContract);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(LaunchAuthorityError::InvalidContract);
        }
    }
    std::fs::canonicalize(path).map_err(|_| LaunchAuthorityError::InvalidContract)
}

fn read_owner_private_uuid(path: &Path) -> Result<[u8; 16], LaunchAuthorityError> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != 16 {
        return Err(LaunchAuthorityError::MissingExpectedStableBinding);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        if metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(LaunchAuthorityError::MissingExpectedStableBinding);
        }
    }
    let bytes: [u8; 16] = std::fs::read(path)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::MissingExpectedStableBinding)?;
    gocode_domain::id::validate_uuid_v7_bytes(&bytes)
        .map_err(|_| LaunchAuthorityError::MissingExpectedStableBinding)?;
    Ok(bytes)
}

#[cfg(unix)]
fn runtime_root_identity(path: &Path) -> [u8; 32] {
    use std::os::unix::ffi::OsStrExt as _;
    Sha256::digest(path.as_os_str().as_bytes()).into()
}

#[cfg(not(unix))]
fn runtime_root_identity(path: &Path) -> [u8; 32] {
    Sha256::digest(path.to_string_lossy().as_bytes()).into()
}

/// Generates non-zero control entropy without exposing it in diagnostics.
pub fn random_control_secret() -> [u8; 32] {
    let mut value = [0; 32];
    while value == [0; 32] {
        OsRng.fill_bytes(&mut value);
    }
    value
}

/// Serves authenticated session renewal and exact-owned shutdown requests.
///
/// Any malformed, replayed, mismatched, or disconnected control exchange
/// terminates the loop fail-closed. The caller uses loop completion as the
/// daemon application's graceful-shutdown signal.
#[cfg(unix)]
pub fn run_control_loop(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedOwnedLaunchV1,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    let mut last_renew_sequence = 0_u64;
    loop {
        let frame = channel.read_control_frame()?;
        if let Ok(renewal) = ProtectedRenewRequestV1::decode_frame(&frame) {
            renewal.verify_exact(&owned_launch, last_renew_sequence, &keys)?;

            let current = local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .current_binding()
                .clone();
            let mut next_session_id = *uuid::Uuid::now_v7().as_bytes();
            while next_session_id == *current.ephemeral().session_id()
                || next_session_id == current.ephemeral().daemon_instance_id().into_bytes()
            {
                next_session_id = *uuid::Uuid::now_v7().as_bytes();
            }
            let mut bootstrap_ticket = random_control_secret();
            let issued_at = session_clock();
            let expires_at = issued_at
                .checked_add(Duration::from_secs(30))
                .ok_or(LaunchAuthorityError::RenewalUnavailable)?;
            let next_binding = RuntimeSessionBinding::new(
                current.stable().clone(),
                current.ephemeral().daemon_instance_id(),
                current.ephemeral().launch_generation(),
                next_session_id,
                current.ephemeral().authorization_epoch(),
                current.ephemeral().sensitivity_ceiling(),
                *current.certificate_sha256(),
            )
            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;

            let issued_at_millis = u64::try_from(issued_at.as_millis())
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let expires_at_millis = u64::try_from(expires_at.as_millis())
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedRenewTicketV1::new(
                &renewal,
                next_session_id,
                bootstrap_ticket,
                issued_at_millis,
                expires_at_millis,
            )?;
            bootstrap_ticket.zeroize();
            ticket.sign(&keys);
            let ticket_frame = Zeroizing::new(
                ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            );
            channel.write_control_frame(&ticket_frame)?;
            last_renew_sequence = renewal.sequence();
            owned_launch = ticket.next_owned_launch();
            continue;
        }

        let shutdown = ProtectedShutdownV1::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(&owned_launch, &keys)?;
        let mut acknowledgement = ProtectedShutdownAckV1::new(owned_launch.clone(), true);
        acknowledgement.sign(&keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}

/// Serves V2 control messages and rejects every V1 frame rather than allowing
/// a provider-bound launch to downgrade its authenticated transcript.
#[cfg(unix)]
pub fn run_control_loop_v2(
    mut channel: ProtectedActivationChannel,
    keys: ProtectedActivationKeys,
    mut owned_launch: ProtectedOwnedLaunchV2,
    local_session_service: Arc<Mutex<LocalSessionService>>,
    session_clock: Arc<dyn Fn() -> Duration + Send + Sync>,
) -> Result<(), LaunchAuthorityError> {
    channel.enter_control_loop()?;
    let mut last_renew_sequence = 0_u64;
    loop {
        let frame = channel.read_control_frame()?;
        if let Ok(renewal) = ProtectedRenewRequestV2::decode_frame(&frame) {
            renewal.verify_exact(&owned_launch, last_renew_sequence, &keys)?;
            let current = local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .current_binding()
                .clone();
            let mut next_session_id = *uuid::Uuid::now_v7().as_bytes();
            while next_session_id == *current.ephemeral().session_id()
                || next_session_id == current.ephemeral().daemon_instance_id().into_bytes()
            {
                next_session_id = *uuid::Uuid::now_v7().as_bytes();
            }
            let mut bootstrap_ticket = random_control_secret();
            let issued_at = session_clock();
            let expires_at = issued_at
                .checked_add(Duration::from_secs(30))
                .ok_or(LaunchAuthorityError::RenewalUnavailable)?;
            let next_binding = RuntimeSessionBinding::new(
                current.stable().clone(),
                current.ephemeral().daemon_instance_id(),
                current.ephemeral().launch_generation(),
                next_session_id,
                current.ephemeral().authorization_epoch(),
                current.ephemeral().sensitivity_ceiling(),
                *current.certificate_sha256(),
            )
            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            local_session_service
                .lock()
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?
                .rotate_protected_bootstrap(next_binding, bootstrap_ticket, issued_at, expires_at)
                .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
            let mut ticket = ProtectedRenewTicketV2::new(
                &renewal,
                next_session_id,
                bootstrap_ticket,
                u64::try_from(issued_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
                u64::try_from(expires_at.as_millis())
                    .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?,
            )?;
            bootstrap_ticket.zeroize();
            ticket.sign(&keys);
            channel.write_control_frame(
                &ticket
                    .encode_frame()
                    .map_err(|_| LaunchAuthorityError::InvalidContract)?,
            )?;
            last_renew_sequence = renewal.sequence();
            owned_launch = ticket.next_owned_launch();
            continue;
        }
        let shutdown = ProtectedShutdownV2::decode_frame(&frame)
            .map_err(|_| LaunchAuthorityError::InvalidContract)?;
        shutdown.verify_exact(&owned_launch, &keys)?;
        let mut acknowledgement = ProtectedShutdownAckV2::new(owned_launch.clone(), true);
        acknowledgement.sign(&keys);
        channel.write_control_frame(
            &acknowledgement
                .encode_frame()
                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
        )?;
        return Ok(());
    }
}

#[cfg(not(unix))]
pub struct ProtectedActivationChannel;

#[cfg(not(unix))]
impl ProtectedActivationChannel {
    pub fn from_inherited_stdin() -> Result<Option<Self>, LaunchAuthorityError> {
        Ok(None)
    }
}
