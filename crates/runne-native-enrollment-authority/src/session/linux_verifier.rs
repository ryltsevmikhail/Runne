//! Linux writer authority-session verifier (B9): the sole producer of a
//! closed `AuthenticatedProviderCredentialWriterSession` for Linux.
//!
//! The publication key, channel, handoff and release tuple come from the
//! verified startup exchange; writer start/image are measured from this live
//! process. Both ordinary V1 and qualified V2 are checked against these facts.
//! V2 must retain its qualification-required ticket through the session split;
//! it cannot mint an ordinary session or fall back to V1 after a failed check.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use runne_provider::{
    BrokerChannelBinding, CredentialWriterSessionAttestationCodec,
    CredentialWriterSessionAttestationV2Codec, PendingCredentialIssueTicketV1,
};

use super::AuthenticatedProviderCredentialWriterSession;

/// The RETAINED startup/rendezvous facts one signed attestation is verified
/// against, together with the attestation bytes and the pending ticket whose
/// commitment it must match.
pub(super) struct LinuxWriterSessionExpectations<'a> {
    pub(super) attestation_bytes: &'a [u8],
    pub(super) retained_publication_key: [u8; 32],
    pub(super) retained_channel_binding: &'a BrokerChannelBinding,
    pub(super) retained_handoff_sha256: [u8; 32],
    pub(super) live_start_sha256: [u8; 32],
    pub(super) live_image_sha256: [u8; 32],
    pub(super) release_tuple_sha256: [u8; 32],
    pub(super) ticket: PendingCredentialIssueTicketV1,
}

/// The owned transports and identities adopted into the closed session once
/// every retained expectation verified.
pub(super) struct LinuxWriterSessionResources {
    pub(super) channel_binding: BrokerChannelBinding,
    pub(super) control: UnixStream,
    pub(super) writer_path: PathBuf,
    pub(super) reader_path: PathBuf,
}

/// Verifies one signed Linux writer session attestation against the RETAINED
/// startup/rendezvous facts and mints the closed authority session.
///
/// # Errors
///
/// Fails closed on any signature, freshness, channel, handoff, or live-fact
/// mismatch — before any effect capability exists.
pub(super) fn authenticate_linux_writer_session(
    expectations: LinuxWriterSessionExpectations<'_>,
    resources: LinuxWriterSessionResources,
) -> Result<AuthenticatedProviderCredentialWriterSession, &'static str> {
    let LinuxWriterSessionExpectations {
        attestation_bytes,
        retained_publication_key,
        retained_channel_binding,
        retained_handoff_sha256,
        live_start_sha256,
        live_image_sha256,
        release_tuple_sha256,
        ticket,
    } = expectations;
    let LinuxWriterSessionResources {
        channel_binding,
        control,
        writer_path,
        reader_path,
    } = resources;
    // Both signed formats have identical identity checks. V2 retains its
    // qualification receiver; its wire version is never normalized to V1.
    macro_rules! verify_record {
        ($codec:ty) => {{
            let attestation =
                <$codec>::decode_and_verify(attestation_bytes, retained_publication_key)
                    .map_err(|_| "attestation signature denied")?;
            if !attestation.is_current_now() {
                return Err("attestation expired");
            }
            if !attestation.matches_handoff(
                &retained_channel_binding.digest().as_bytes(),
                &retained_publication_key,
                &retained_handoff_sha256,
            ) {
                return Err("channel or handoff mismatch");
            }
            if !attestation.matches_writer_live_facts(&live_start_sha256, &live_image_sha256) {
                return Err("live writer facts mismatch");
            }
            if !attestation.matches_pending_issue_ticket(&ticket) {
                return Err("ticket commitment mismatch");
            }
            if !attestation
                .release_binding_expectation()
                .matches(&release_tuple_sha256)
            {
                return Err("release tuple mismatch");
            }
        }};
    }
    match attestation_bytes.first() {
        Some(1) if !ticket.is_qualified() => {
            verify_record!(CredentialWriterSessionAttestationCodec);
        }
        Some(2) if ticket.is_qualified() => {
            verify_record!(CredentialWriterSessionAttestationV2Codec);
        }
        _ => return Err("attestation version denied"),
    }
    Ok(AuthenticatedProviderCredentialWriterSession::mint(
        super::VerifiedEnrollmentSession::Linux(Box::new((
            control,
            channel_binding,
            ticket,
            writer_path,
            reader_path,
        ))),
    ))
}
