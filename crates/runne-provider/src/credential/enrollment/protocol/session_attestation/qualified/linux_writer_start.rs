//! First-party Linux writer startup + CONTROL binding (extracted from
//! platform-desktop so the authority crate can run the WHOLE writer-side
//! trust path without a dependency cycle; platform-desktop re-exports for
//! its daemon-side fixtures). No new trust: the same existing protocol,
//! domains, and transcript tags as `daemon_evidence.rs`.

use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;

use ed25519_dalek::SigningKey;
use rand::RngCore as _;
use rand::rngs::OsRng;
use runne_api::CredentialBrokerWriterStartupAuthenticator;

use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::receiver::bind_verified_linux_attestation;

/// Closed failure of the writer startup exchange (same shape as the
/// platform BrokerHandoffError; local so no new cross-crate edge is created).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartupError {
    Rejected,
    Unavailable,
}
use super::SignedCredentialWriterSessionAttestationV2;
use crate::credential::enrollment::PendingCredentialIssueTicketV1;

// Wire constants — MUST stay byte-identical to the daemon_evidence domains
// the challenge comes from (single protocol, two crate locations).
const CHALLENGE_BYTES: usize = 128;
const RECORD_BYTES: usize = CHALLENGE_BYTES + 128;
const FRAME_BYTES: usize = RECORD_BYTES + 32;
const CHALLENGE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-evidence/v1/challenge\0";
const RESPONSE_TAG: &[u8] = b"gocode/provider-credential-broker/daemon-evidence/v1/response\0";
const STARTUP_PAYLOAD_BYTES: usize = 160;
const STARTUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// One writer startup outcome: the real kill keypair plus the daemon-PROOF-
/// authenticated rendezvous facts and the INDEPENDENT release tuple adopted
/// from the verified startup payload — the retained origin for every later
/// expectation. Fields are read-only facts of a completed proof exchange.
pub struct LinuxWriterStartup {
    /// The writer-generated kill publication key sent to the daemon.
    pub kill_public_key: [u8; 32],
    /// The retained private kill half; never transmitted.
    pub kill_signing_key: SigningKey,
    /// Daemon-proof-authenticated rendezvous channel binding.
    pub channel_binding: [u8; 32],
    /// Daemon-proof-authenticated publication key.
    pub publication_public_key: [u8; 32],
    /// The INDEPENDENT canonical build-time release tuple from the sealed
    /// startup payload (MAC-echo bound) — never read back from an
    /// attestation.
    pub release_tuple: [u8; 32],
}

/// Live self-measurements of this writer process (start identity + image).
pub fn linux_writer_self_measurements() -> Result<([u8; 32], [u8; 32]), StartupError> {
    let pid = std::process::id();
    let stat =
        std::fs::read_to_string(format!("/proc/{pid}/stat")).map_err(|_| StartupError::Rejected)?;
    let tail = stat
        .rsplit_once(')')
        .map(|(_, tail)| tail)
        .ok_or(StartupError::Rejected)?;
    let start_time = tail
        .split_whitespace()
        .nth(19)
        .ok_or(StartupError::Rejected)?;
    let mut digest = Sha256::new();
    digest.update(b"gocode.provider-credential-writer.start.v1");
    digest.update(pid.to_be_bytes());
    digest.update(start_time.as_bytes());
    let start: [u8; 32] = digest.finalize().into();
    let image = std::fs::read("/proc/self/exe")
        .map_err(|_| StartupError::Rejected)
        .map(|bytes| <[u8; 32]>::from(Sha256::digest(&bytes)))?;
    Ok((start, image))
}

/// Fills a sealed payload containing only one writer-scoped startup key.
#[must_use]
pub fn encode_linux_writer_startup_payload(
    authenticator: &CredentialBrokerWriterStartupAuthenticator,
) -> Zeroizing<[u8; 160]> {
    authenticator.handoff_payload()
}

/// Writer side of the startup handshake over the inherited one-shot duplex
/// transport: reads the sealed scoped key, verifies
/// the daemon challenge proof, adopts only daemon-authenticated facts,
/// self-measures, generates a real kill keypair, and answers in the exact
/// existing transcript domains.
///
/// # Errors
///
/// Fails closed on transport, challenge-proof, or self-measurement failure.
pub fn respond_linux_writer_startup(
    mut transport: UnixStream,
) -> Result<LinuxWriterStartup, StartupError> {
    transport
        .set_read_timeout(Some(STARTUP_TIMEOUT))
        .and_then(|()| transport.set_write_timeout(Some(STARTUP_TIMEOUT)))
        .map_err(|_| StartupError::Unavailable)?;
    let mut payload = Zeroizing::new([0; STARTUP_PAYLOAD_BYTES]);
    transport
        .read_exact(&mut *payload)
        .map_err(|_| StartupError::Rejected)?;
    let authenticator = CredentialBrokerWriterStartupAuthenticator::from_handoff_payload(&payload)
        .ok_or(StartupError::Rejected)?;
    drop(payload);
    answer_challenge(&mut transport, &authenticator)
}

impl LinuxWriterStartup {
    /// Binds the ticket's qualified receiver from the SIGNED control
    /// attestation using ONLY this startup's retained facts — the signed
    /// release tuple is compared against the INDEPENDENTLY retained startup
    /// tuple before any binding. No caller-supplied arrays exist.
    ///
    /// # Errors
    ///
    /// Fails closed on signature, freshness, or tuple mismatch.
    pub fn bind_verified_control(
        &self,
        attestation: &SignedCredentialWriterSessionAttestationV2,
        attestation_bytes: &[u8],
        ticket: PendingCredentialIssueTicketV1,
    ) -> Result<PendingCredentialIssueTicketV1, StartupError> {
        if !attestation
            .release_binding_expectation()
            .matches(&self.release_tuple)
        {
            return Err(StartupError::Rejected);
        }
        bind_verified_linux_attestation(
            ticket,
            attestation_bytes,
            self.publication_public_key,
            self.release_tuple,
        )
        .map_err(|_| StartupError::Rejected)
    }
}

fn answer_challenge(
    transport: &mut UnixStream,
    authenticator: &CredentialBrokerWriterStartupAuthenticator,
) -> Result<LinuxWriterStartup, StartupError> {
    let mut challenge = [0; CHALLENGE_BYTES];
    transport
        .read_exact(&mut challenge)
        .map_err(|_| StartupError::Rejected)?;
    let proof: [u8; 32] = challenge[96..]
        .try_into()
        .map_err(|_| StartupError::Rejected)?;
    if challenge[..32] != authenticator.channel()
        || challenge[32..64] != authenticator.publication_key()
        || challenge[64..96] != authenticator.nonce()
        || !authenticator
            .verifies_daemon_proof(&transcript(CHALLENGE_TAG, &challenge[..96]), &proof)
    {
        return Err(StartupError::Rejected);
    }
    let channel_binding = authenticator.channel();
    let publication_public_key = authenticator.publication_key();
    let (start, image) = linux_writer_self_measurements()?;
    let mut seed = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    let kill_signing_key = SigningKey::from_bytes(&seed);
    let kill_public_key = kill_signing_key.verifying_key().to_bytes();
    let mut record = [0; RECORD_BYTES];
    record[..CHALLENGE_BYTES].copy_from_slice(&challenge);
    record[CHALLENGE_BYTES..160].copy_from_slice(&start);
    record[160..192].copy_from_slice(&image);
    record[192..224].copy_from_slice(&authenticator.release());
    record[224..].copy_from_slice(&kill_public_key);
    let proof = authenticator.authenticate_writer_proof(&transcript(RESPONSE_TAG, &record));
    let mut frame = [0; FRAME_BYTES];
    frame[..RECORD_BYTES].copy_from_slice(&record);
    frame[RECORD_BYTES..].copy_from_slice(&proof);
    transport
        .write_all(&frame)
        .and_then(|()| transport.shutdown(std::net::Shutdown::Write))
        .map_err(|_| StartupError::Rejected)?;
    Ok(LinuxWriterStartup {
        kill_public_key,
        kill_signing_key,
        channel_binding,
        publication_public_key,
        release_tuple: authenticator.release(),
    })
}

fn transcript(tag: &[u8], record: &[u8]) -> Vec<u8> {
    let mut transcript = Vec::with_capacity(tag.len() + record.len());
    transcript.extend_from_slice(tag);
    transcript.extend_from_slice(record);
    transcript
}
