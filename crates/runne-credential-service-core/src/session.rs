use std::collections::HashMap;

use rand::{RngCore as _, rngs::OsRng};
use runne_api::{
    CredentialServiceRegistrationAck, CredentialServiceRegistrationBinding,
    CredentialServiceSessionAuthenticator,
};
use runne_provider::{
    CredentialEnrollmentError, CredentialServiceDisposition, CredentialServiceEndpointRole,
    CredentialServiceEpoch, CredentialServiceIngressRequest, CredentialServiceProtocolCodec,
    CredentialServiceReply, CredentialServiceReplyFrame,
};

use crate::admission::AdmissionLedger;

mod registration;
mod runtime;
// Gate A deliberately exposes no production qualification ingress. The private staged
// API stays compiled and tested below until the future atomic receiver wires it in.
#[allow(
    dead_code,
    reason = "Gate A qualification staging has zero production callers"
)]
mod qualification;
mod validation;

pub use qualification::QualificationResourceBudget;

const MAX_CHALLENGES: usize = 64;
const CHALLENGE_TTL_MILLIS: u64 = 5_000;

/// Result of atomically installing one authenticated registration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialRegistrationOutcome {
    /// No session existed for the installation owner.
    Installed,
    /// The exact current registration was replayed without changing state.
    Idempotent,
    /// A strictly newer protected registration replaced the old one.
    Superseded,
}

/// Pre-context ingress failures require connection invalidation and no reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CredentialServiceIngressFailure {
    /// No authenticated request context exists from which to build a safe reply.
    Invalidate,
}

/// Non-authorizing activity snapshot for the service idle timer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CredentialServiceActivity {
    prevents_idle: bool,
    next_deadline: Option<u64>,
}

impl CredentialServiceActivity {
    /// Whether ephemeral core-owned state currently prevents idle shutdown.
    #[must_use]
    pub const fn prevents_idle(self) -> bool {
        self.prevents_idle
    }

    /// Earliest expiry at which the service should poll again.
    #[must_use]
    pub const fn next_deadline_unix_millis(self) -> Option<u64> {
        self.next_deadline
    }
}

/// Unsafe-free, ephemeral credential service state machine.
pub struct CredentialServiceCore {
    epoch: CredentialServiceEpoch,
    sessions: HashMap<[u8; 32], ActiveSession>,
    admissions: AdmissionLedger,
    challenges: HashMap<[u8; 16], u64>,
}

struct ActiveSession {
    binding: CredentialServiceRegistrationBinding,
    authenticator: CredentialServiceSessionAuthenticator,
    ack: CredentialServiceRegistrationAck,
    last_sequence: u64,
    read_receipts: HashMap<[u8; 32], u64>,
}

impl CredentialServiceCore {
    /// Creates one service instance with a fresh non-zero OS-CSPRNG epoch.
    ///
    /// # Errors
    ///
    /// Returns `EntropyUnavailable` when the operating system cannot issue entropy.
    pub fn new() -> Result<Self, CredentialEnrollmentError> {
        Self::new_with_entropy(|bytes| OsRng.try_fill_bytes(bytes).map_err(|_| ()))
    }

    fn new_with_entropy(
        fill: impl FnOnce(&mut [u8; 16]) -> Result<(), ()>,
    ) -> Result<Self, CredentialEnrollmentError> {
        let mut epoch = [0_u8; 16];
        fill(&mut epoch).map_err(|()| CredentialEnrollmentError::EntropyUnavailable)?;
        Self::from_epoch(epoch)
    }

    fn from_epoch(epoch: [u8; 16]) -> Result<Self, CredentialEnrollmentError> {
        Ok(Self {
            epoch: CredentialServiceEpoch::from_bytes(epoch)
                .map_err(|_| CredentialEnrollmentError::EntropyUnavailable)?,
            sessions: HashMap::new(),
            admissions: AdmissionLedger::new(),
            challenges: HashMap::new(),
        })
    }

    #[cfg(test)]
    pub(crate) fn with_test_epoch(epoch: [u8; 16]) -> Result<Self, CredentialEnrollmentError> {
        Self::from_epoch(epoch)
    }

    #[cfg(test)]
    pub(crate) fn with_test_entropy(
        fill: impl FnOnce(&mut [u8; 16]) -> Result<(), ()>,
    ) -> Result<Self, CredentialEnrollmentError> {
        Self::new_with_entropy(fill)
    }

    /// Issues a bounded service nonce for a strict payload-free Desktop request.
    ///
    /// # Errors
    ///
    /// Returns `Invalidate` when no trustworthy Desktop request context exists.
    pub fn challenge(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
    ) -> Result<CredentialServiceReplyFrame, CredentialServiceIngressFailure> {
        self.challenge_with_entropy(listener_role, bytes, now, |nonce| {
            OsRng.try_fill_bytes(nonce).map_err(|_| ())
        })
    }

    #[cfg(test)]
    pub(crate) fn challenge_with_test_nonce(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
        nonce: [u8; 16],
    ) -> Result<CredentialServiceReplyFrame, CredentialServiceIngressFailure> {
        self.challenge_with_entropy(listener_role, bytes, now, |out| {
            *out = nonce;
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn challenge_with_test_entropy(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
        fill: impl FnOnce(&mut [u8; 16]) -> Result<(), ()>,
    ) -> Result<CredentialServiceReplyFrame, CredentialServiceIngressFailure> {
        self.challenge_with_entropy(listener_role, bytes, now, fill)
    }

    fn challenge_with_entropy(
        &mut self,
        listener_role: CredentialServiceEndpointRole,
        bytes: &[u8],
        now: u64,
        fill: impl FnOnce(&mut [u8; 16]) -> Result<(), ()>,
    ) -> Result<CredentialServiceReplyFrame, CredentialServiceIngressFailure> {
        if listener_role != CredentialServiceEndpointRole::Desktop {
            return Err(CredentialServiceIngressFailure::Invalidate);
        }
        let request = CredentialServiceProtocolCodec::decode_desktop_request(bytes)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)?;
        let context = request.context();
        if !matches!(
            request,
            CredentialServiceIngressRequest::RegistrationChallenge
        ) {
            return Err(CredentialServiceIngressFailure::Invalidate);
        }
        self.challenges.retain(|_, expiry| *expiry > now);
        let mut nonce = [0_u8; 16];
        let expiry = now.checked_add(CHALLENGE_TTL_MILLIS);
        let reply = if fill(&mut nonce).is_err()
            || nonce == [0; 16]
            || self.challenges.contains_key(&nonce)
            || self.challenges.len() == MAX_CHALLENGES
            || expiry.is_none()
        {
            CredentialServiceReply::Rejected(CredentialServiceDisposition::Unavailable)
        } else {
            self.challenges.insert(nonce, expiry.unwrap_or(now));
            CredentialServiceReply::RegistrationChallenge {
                epoch: self.epoch,
                nonce,
            }
        };
        CredentialServiceProtocolCodec::encode_reply(context, reply)
            .map_err(|_| CredentialServiceIngressFailure::Invalidate)
    }

    /// Purges expired ephemeral state and reports idle ownership without exposing it.
    ///
    /// Protected-shutdown authenticated clearing remains a later control-protocol transition.
    pub fn poll(&mut self, now: u64) -> CredentialServiceActivity {
        self.challenges.retain(|_, expiry| *expiry > now);
        let expired: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(owner, session)| {
                (session.binding.expires_at_unix_millis() <= now).then_some(*owner)
            })
            .collect();
        for owner in expired {
            self.sessions.remove(&owner);
            self.admissions.clear_owner(owner);
        }
        for session in self.sessions.values_mut() {
            session.read_receipts.retain(|_, expiry| *expiry > now);
        }
        self.admissions.poll(now);
        let next_deadline = self
            .challenges
            .values()
            .copied()
            .chain(
                self.sessions
                    .values()
                    .map(|session| session.binding.expires_at_unix_millis()),
            )
            .chain(self.admissions.deadlines())
            .chain(
                self.sessions
                    .values()
                    .flat_map(|session| session.read_receipts.values().copied()),
            )
            .min();
        CredentialServiceActivity {
            prevents_idle: !self.challenges.is_empty()
                || !self.sessions.is_empty()
                || !self.admissions.is_empty(),
            next_deadline,
        }
    }
}
