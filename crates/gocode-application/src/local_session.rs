//! One-time local bootstrap proofs and short-lived session authorities.

use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};

use gocode_api::RuntimeSessionBinding;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

const CHALLENGE_TTL: Duration = Duration::from_secs(30);
const SESSION_TTL: Duration = Duration::from_secs(10 * 60);
const MAX_CHALLENGES: usize = 32;
const MAX_ISSUED_PER_MINUTE: usize = 60;
const MAX_SESSIONS_PER_PRINCIPAL: usize = 8;
const MAX_SESSIONS: usize = 32;
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
    bootstrap_secret: Zeroizing<[u8; 32]>,
    challenges: HashMap<LocalSessionChallengeId, Challenge>,
    issued: VecDeque<Duration>,
    sessions: HashMap<[u8; 32], Session>,
    authorization_epoch: u64,
}

impl LocalSessionService {
    /// Builds a service for exactly one daemon launch binding.
    pub fn new(binding: RuntimeSessionBinding, bootstrap_secret: [u8; 32]) -> Self {
        Self {
            authorization_epoch: binding.ephemeral().authorization_epoch(),
            binding,
            bootstrap_secret: Zeroizing::new(bootstrap_secret),
            challenges: HashMap::new(),
            issued: VecDeque::new(),
            sessions: HashMap::new(),
        }
    }

    /// Issues one challenge using caller-supplied deterministic entropy and monotonic time.
    pub fn issue_challenge(
        &mut self,
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        now: Duration,
    ) -> Result<LocalSessionChallenge, LocalSessionError> {
        self.prune(now);
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
        let mut mac = HmacSha256::new_from_slice(self.bootstrap_secret.as_ref())
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
            expires_at_monotonic: now + SESSION_TTL,
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
        Ok(authenticated)
    }

    /// Revokes all authorities from an earlier authorization epoch.
    pub fn set_authorization_epoch(&mut self, epoch: u64) {
        self.authorization_epoch = epoch;
        self.sessions.retain(|_, session| session.epoch == epoch);
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
