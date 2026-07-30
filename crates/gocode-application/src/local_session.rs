//! One-time local bootstrap proofs and short-lived session authorities.

use std::{
    collections::{HashMap, VecDeque},
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

/// In-memory bounded proof and authority service.
pub struct LocalSessionService {
    binding: RuntimeSessionBinding,
    bootstrap_secret: Option<Zeroizing<[u8; 32]>>,
    bootstrap_expires_at: Option<Duration>,
    bootstrap_policy: BootstrapPolicy,
    challenges: HashMap<LocalSessionChallengeId, Challenge>,
    issued: VecDeque<Duration>,
    sessions: HashMap<[u8; 32], Session>,
    authorization_epoch: u64,
    sensitivity_ceiling: Sensitivity,
}

impl LocalSessionService {
    /// Builds a service for exactly one daemon launch binding.
    pub fn new(binding: RuntimeSessionBinding, bootstrap_secret: [u8; 32]) -> Self {
        Self::with_policy(
            binding,
            bootstrap_secret,
            BootstrapPolicy::ReusableExternal,
            None,
        )
    }

    /// Builds a service whose bootstrap proof can succeed exactly once before
    /// the supplied monotonic deadline.
    pub fn new_protected(
        binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        now: Duration,
        expires_at: Duration,
    ) -> Result<Self, LocalSessionError> {
        if bootstrap_secret == [0; 32]
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(Self::with_policy(
            binding,
            bootstrap_secret,
            BootstrapPolicy::OneTimeProtected,
            Some(expires_at),
        ))
    }

    fn with_policy(
        binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        bootstrap_policy: BootstrapPolicy,
        bootstrap_expires_at: Option<Duration>,
    ) -> Self {
        Self {
            authorization_epoch: binding.ephemeral().authorization_epoch(),
            sensitivity_ceiling: binding.ephemeral().sensitivity_ceiling(),
            binding,
            bootstrap_secret: Some(Zeroizing::new(bootstrap_secret)),
            bootstrap_expires_at,
            bootstrap_policy,
            challenges: HashMap::new(),
            issued: VecDeque::new(),
            sessions: HashMap::new(),
        }
    }

    /// Returns the current exact in-memory session binding.
    pub const fn current_binding(&self) -> &RuntimeSessionBinding {
        &self.binding
    }

    /// Issues one challenge using caller-supplied deterministic entropy and monotonic time.
    pub fn issue_challenge(
        &mut self,
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        now: Duration,
    ) -> Result<LocalSessionChallenge, LocalSessionError> {
        self.prune(now);
        self.enforce_bootstrap_deadline(now)?;
        if self.bootstrap_secret.is_none() {
            return Err(LocalSessionError::Unauthorized);
        }
        if self.challenges.len() >= MAX_CHALLENGES || self.issued.len() >= MAX_ISSUED_PER_MINUTE {
            return Err(LocalSessionError::Unavailable);
        }
        let id =
            LocalSessionChallengeId(server_nonce[..16].try_into().expect("fixed nonce prefix"));
        if self.challenges.contains_key(&id) {
            return Err(LocalSessionError::Unavailable);
        }
        self.challenges.insert(
            id,
            Challenge {
                client_nonce,
                server_nonce,
                issued_at: now,
            },
        );
        self.issued.push_back(now);
        Ok(LocalSessionChallenge { id, server_nonce })
    }

    /// Verifies and consumes a challenge before issuing a ten-minute authority.
    pub fn authenticate(
        &mut self,
        id: LocalSessionChallengeId,
        proof: BootstrapProof,
        authority_bytes: [u8; 32],
        now: Duration,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.prune(now);
        self.enforce_bootstrap_deadline(now)?;
        let Some(challenge) = self.challenges.remove(&id) else {
            return Err(LocalSessionError::Unauthorized);
        };
        if now.saturating_sub(challenge.issued_at) > CHALLENGE_TTL || authority_bytes == [0; 32] {
            return Err(LocalSessionError::Unauthorized);
        }
        let transcript = bootstrap_proof_transcript(
            &self.binding,
            challenge.server_nonce,
            challenge.client_nonce,
        );
        let Some(bootstrap_secret) = self.bootstrap_secret.as_ref() else {
            return Err(LocalSessionError::Unauthorized);
        };
        let mut mac = HmacSha256::new_from_slice(bootstrap_secret.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(&transcript);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        if !bool::from(expected.ct_eq(&proof.0)) {
            return Err(LocalSessionError::Unauthorized);
        }
        let principal = self.binding.stable().principal_id().as_str();
        if self.sessions.len() >= MAX_SESSIONS
            || self
                .sessions
                .values()
                .filter(|session| {
                    session
                        .authenticated
                        .binding
                        .stable()
                        .principal_id()
                        .as_str()
                        == principal
                })
                .count()
                >= MAX_SESSIONS_PER_PRINCIPAL
        {
            return Err(LocalSessionError::Unavailable);
        }
        let authenticated = AuthenticatedRuntimeSession {
            binding: self.binding.clone(),
            expires_at_monotonic: now + LOCAL_RUNTIME_SESSION_TTL,
        };
        self.sessions.insert(
            authority_bytes,
            Session {
                authenticated: authenticated.clone(),
                authority: RuntimeSessionAuthority(Zeroizing::new(authority_bytes)),
                epoch: self.authorization_epoch,
                generation: self.binding.ephemeral().launch_generation(),
            },
        );
        if self.bootstrap_policy == BootstrapPolicy::OneTimeProtected {
            self.bootstrap_secret.take();
            self.bootstrap_expires_at = None;
            self.challenges.clear();
        }
        Ok(authenticated)
    }

    /// Installs the next one-time bootstrap for the exact same owned launch.
    ///
    /// Rotation changes only the HTTP session identity. Stable authority,
    /// daemon instance, launch generation, authorization epoch, sensitivity,
    /// and certificate identity must remain exact.
    pub fn rotate_protected_bootstrap(
        &mut self,
        binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        now: Duration,
        expires_at: Duration,
    ) -> Result<(), LocalSessionError> {
        let current_ephemeral = self.binding.ephemeral();
        let next_ephemeral = binding.ephemeral();
        if self.bootstrap_policy != BootstrapPolicy::OneTimeProtected
            || bootstrap_secret == [0; 32]
            || self.binding.stable() != binding.stable()
            || current_ephemeral.daemon_instance_id() != next_ephemeral.daemon_instance_id()
            || current_ephemeral.launch_generation() != next_ephemeral.launch_generation()
            || current_ephemeral.session_id() == next_ephemeral.session_id()
            || current_ephemeral.authorization_epoch() != next_ephemeral.authorization_epoch()
            || current_ephemeral.sensitivity_ceiling() != next_ephemeral.sensitivity_ceiling()
            || self.binding.certificate_sha256() != binding.certificate_sha256()
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        self.binding = binding;
        self.bootstrap_secret = Some(Zeroizing::new(bootstrap_secret));
        self.bootstrap_expires_at = Some(expires_at);
        self.challenges.clear();
        self.sessions.clear();
        Ok(())
    }

    fn enforce_bootstrap_deadline(&mut self, now: Duration) -> Result<(), LocalSessionError> {
        if self
            .bootstrap_expires_at
            .is_some_and(|expires_at| now > expires_at)
        {
            self.bootstrap_secret.take();
            self.bootstrap_expires_at = None;
            self.challenges.clear();
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(())
    }

    /// Revokes all authorities from an earlier authorization epoch.
    pub fn set_authorization_epoch(&mut self, epoch: u64) {
        self.authorization_epoch = epoch;
        self.sessions.retain(|_, session| session.epoch == epoch);
    }

    /// Updates the replay sensitivity ceiling observed by current delivery
    /// leases without minting a replacement transport authority.
    pub fn set_sensitivity_ceiling(&mut self, ceiling: Sensitivity) {
        self.sensitivity_ceiling = ceiling;
    }

    /// Returns the current replay authorization for the bound principal and
    /// daemon generation.
    pub fn current_replay_authorization(
        &self,
        principal_id: &str,
        generation: u64,
    ) -> Result<LocalReplayAuthorizationState, LocalSessionError> {
        if principal_id != self.binding.stable().principal_id().as_str()
            || generation != self.binding.ephemeral().launch_generation()
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(LocalReplayAuthorizationState {
            authorization_epoch: self.authorization_epoch,
            sensitivity_ceiling: self.sensitivity_ceiling,
        })
    }

    /// Validates a session against the service's current binding.
    pub fn authorize_wire(
        &mut self,
        authority: &[u8; 32],
        now: Duration,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.authorize_wire_for_binding(authority, &self.binding.clone(), now)
    }

    /// Validates a session against an explicit launch binding, for composition roots that rotate generations.
    pub fn authorize_wire_for_binding(
        &mut self,
        authority: &[u8; 32],
        binding: &RuntimeSessionBinding,
        now: Duration,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.prune(now);
        let Some(session) = self.sessions.get(authority) else {
            return Err(LocalSessionError::Unauthorized);
        };
        if !session.authority.verifies(authority)
            || session.epoch != self.authorization_epoch
            || session.generation != binding.ephemeral().launch_generation()
            || session.authenticated.binding != *binding
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(session.authenticated.clone())
    }

    fn prune(&mut self, now: Duration) {
        self.challenges
            .retain(|_, challenge| now.saturating_sub(challenge.issued_at) <= CHALLENGE_TTL);
        while self
            .issued
            .front()
            .is_some_and(|issued| now.saturating_sub(*issued) >= Duration::from_secs(60))
        {
            self.issued.pop_front();
        }
        self.sessions
            .retain(|_, session| now < session.authenticated.expires_at_monotonic);
    }
}

/// Exact binary bootstrap-proof transcript. No JSON canonicalization is used.
pub fn bootstrap_proof_transcript(
    binding: &RuntimeSessionBinding,
    server_nonce: [u8; 32],
    client_nonce: [u8; 32],
) -> Vec<u8> {
    let stable = binding.stable();
    let mut output = b"gocode/local-runtime/bootstrap-proof/v2\0".to_vec();
    output.extend_from_slice(&2_u32.to_be_bytes());
    output.extend_from_slice(binding.certificate_sha256());
    output.extend_from_slice(&server_nonce);
    output.extend_from_slice(&client_nonce);
    output.extend_from_slice(stable.authority_id());
    append_string(&mut output, stable.principal_id().as_str());
    output.extend_from_slice(stable.lineage_id().as_bytes());
    output.extend_from_slice(&binding.ephemeral().daemon_instance_id().into_bytes());
    output.extend_from_slice(&binding.ephemeral().launch_generation().to_be_bytes());
    append_string(&mut output, stable.profile_id());
    output.extend_from_slice(stable.schema_hash());
    output.extend_from_slice(stable.capability_digest());
    output
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &(u16::try_from(value.len()).expect("API identity and profile are bounded")).to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}
