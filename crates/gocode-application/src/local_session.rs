//! One-time local bootstrap proofs and short-lived session authorities.

use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::Duration,
};

use gocode_api::{LOCAL_RUNTIME_SESSION_TTL, RuntimeSessionBinding};
use gocode_domain::event::Sensitivity;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const MAX_CHALLENGES: usize = 32;
const MAX_ISSUED_PER_MINUTE: usize = 60;
const MAX_SESSIONS_PER_PRINCIPAL: usize = 8;
const MAX_SESSIONS: usize = 32;
const MAX_PROTECTED_BOOTSTRAP_TTL: Duration = Duration::from_secs(30);
type HmacSha256 = Hmac<Sha256>;

/// Opaque, memory-only authority for one authenticated local runtime session.
///
/// ```compile_fail
/// use gocode_application::local_session::RuntimeSessionAuthority;
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<RuntimeSessionAuthority>();
/// ```
///
/// ```compile_fail
/// use gocode_application::local_session::RuntimeSessionAuthority;
/// fn requires_display<T: core::fmt::Display>() {}
/// requires_display::<RuntimeSessionAuthority>();
/// ```
#[derive(Clone)]
pub struct RuntimeSessionAuthority(Zeroizing<[u8; 32]>);

impl RuntimeSessionAuthority {
    /// Constant-time verification against raw authority material held by the service.
    pub fn verifies(&self, candidate: &[u8; 32]) -> bool {
        bool::from(self.0.as_ref().ct_eq(candidate))
    }
}

/// A proof HMAC supplied by the desktop after reading the one-time bootstrap secret.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BootstrapProof([u8; 32]);

impl BootstrapProof {
    /// Wraps exactly 32 HMAC-SHA-256 bytes.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the transmitted HMAC proof bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Server-issued opaque challenge identifier.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct LocalSessionChallengeId(pub [u8; 16]);

/// Public challenge material returned to the local desktop.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LocalSessionChallenge {
    pub id: LocalSessionChallengeId,
    pub server_nonce: [u8; 32],
}

/// Session identity inserted into a successfully authenticated request.
#[derive(Clone)]
pub struct AuthenticatedRuntimeSession {
    /// Binding authenticated by the bootstrap proof.
    pub binding: RuntimeSessionBinding,
    /// Absolute monotonic expiry measured from daemon launch.
    pub expires_at_monotonic: Duration,
}

/// Closed local-session failure vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalSessionError {
    Unauthorized,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BootstrapPolicy {
    ReusableExternal,
    OneTimeProtected,
}

/// Current daemon-owned replay authorization values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalReplayAuthorizationState {
    authorization_epoch: u64,
    sensitivity_ceiling: Sensitivity,
}

impl LocalReplayAuthorizationState {
    pub const fn authorization_epoch(self) -> u64 {
        self.authorization_epoch
    }

    pub const fn sensitivity_ceiling(self) -> Sensitivity {
        self.sensitivity_ceiling
    }
}

#[derive(Clone)]
struct Challenge {
    client_nonce: [u8; 32],
    server_nonce: [u8; 32],
    issued_at: Duration,
}
#[derive(Clone)]
struct Session {
    authenticated: AuthenticatedRuntimeSession,
    authority: RuntimeSessionAuthority,
    epoch: u64,
    generation: u64,
}

/// Bounded local-session authority service.
///
/// The transitional challenge path is memory-only. Bootstrap-v3 reservation,
/// replay, tombstone, attempt-fence, and clock state is delegated to the
/// injected [`BootstrapReservationStore`].
pub struct LocalSessionService {
    binding: RuntimeSessionBinding,
    launch_authority_id: [u8; 16],
    executable_sha256: [u8; 32],
    bootstrap_secret: Option<Zeroizing<[u8; 32]>>,
    bootstrap_expires_at: Option<Duration>,
    bootstrap_policy: BootstrapPolicy,
    challenges: HashMap<LocalSessionChallengeId, Challenge>,
    issued: VecDeque<Duration>,
    sessions: HashMap<[u8; 32], Session>,
    authorization_epoch: u64,
    sensitivity_ceiling: Sensitivity,
    reservation_store: Arc<dyn BootstrapReservationStore>,
}

mod bootstrap_reservation_store;
mod bootstrap_v3;
mod bootstrap_v3_transcript;
pub use bootstrap_reservation_store::*;
pub use bootstrap_v3::*;

include!("local_session/service_constructors.rs");
include!("local_session/service.rs");
include!("local_session/transcript.rs");
