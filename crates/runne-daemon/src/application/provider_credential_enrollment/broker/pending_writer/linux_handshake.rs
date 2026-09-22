//! Linux writer startup handshake receiver (B8 stage 1).
//!
//! Reuses the existing platform-neutral daemon-evidence protocol: the daemon
//! challenges with its OWN rendezvous facts (channel binding, publication
//! key, nonce) and receives the transfer-authority-authenticated writer
//! evidence — including the writer-generated kill publication key — over one
//! one-shot transport. The frame is then cross-bound to the daemon's LIVE
//! remeasure of the exact pidfd-retained process, so evidence replayed from
//! any other writer is denied. No raw facts session minter exists here: the
//! only product is a verified handshake feeding the already-closed writer
//! authority constructor.

use std::os::unix::net::UnixStream;

use runne_api::{
    ProviderCredentialBrokerTransferAuthority, ProviderCredentialEnrollmentHostError as Error,
};
use runne_platform_desktop::provider_credential_broker::linux_writer_admission::{
    VerifiedLinuxWriterAdmission, admit_linux_writer,
};
use runne_platform_desktop::provider_credential_broker::{
    UnixRetainedWriterProcess, receive_daemon_owned_writer_measurements,
    receive_linux_writer_startup,
};
use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

use super::super::pending::PendingBrokerRendezvousBinding;
use super::super::rendezvous::DaemonBrokerAuthority;
use super::VerifiedLinuxWriterWithDaemonAuthority;

/// Verified startup handshake: live pidfd admission plus the authenticated
/// writer kill publication key from the signed evidence frame.
pub(crate) struct VerifiedLinuxWriterHandshake {
    admission: VerifiedLinuxWriterAdmission,
    kill_public_key: [u8; 32],
}

impl VerifiedLinuxWriterHandshake {
    #[must_use]
    pub(crate) const fn admission(&self) -> &VerifiedLinuxWriterAdmission {
        &self.admission
    }

    #[must_use]
    pub(crate) const fn kill_public_key(&self) -> [u8; 32] {
        self.kill_public_key
    }

    /// The verified caller path for the kill key: feeds the closed writer
    /// authority constructor with the handshake-authenticated key.
    pub(crate) const fn into_admitted_writer(
        self,
        binding: PendingBrokerRendezvousBinding,
        authority: DaemonBrokerAuthority,
        process: UnixRetainedWriterProcess,
    ) -> VerifiedLinuxWriterWithDaemonAuthority {
        VerifiedLinuxWriterWithDaemonAuthority::from_admitted_parts(
            binding,
            authority,
            process,
            self.admission,
            Some(self.kill_public_key),
        )
    }
}

/// Receives the writer startup evidence on one one-shot transport and
/// cross-binds it to the daemon's live remeasure of the retained process.
///
/// # Errors
///
/// Fails closed on any challenge, proof, binding, or live-fact mismatch.
pub(crate) fn receive_linux_writer_handshake(
    transport: UnixStream,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    launch_secret: &[u8; 32],
    expected_release_tuple: [u8; 32],
    rendezvous: &DaemonBrokerAuthority,
    process: &UnixRetainedWriterProcess,
    spec: &VerifiedWriterLaunchSpec,
) -> Result<VerifiedLinuxWriterHandshake, Error> {
    let admission = admit_linux_writer(process, spec).map_err(|_| Error::AccessDenied)?;
    let kill_public_key = crate_sanitize(receive_linux_writer_startup(
        transport,
        transfer_authority,
        launch_secret,
        expected_release_tuple,
        rendezvous.channel_binding(),
        rendezvous.publication_public_key(),
        admission.start_identity(),
        admission.image_digest(),
    ))?;
    Ok(VerifiedLinuxWriterHandshake {
        admission,
        kill_public_key,
    })
}

/// Evidence core: every expected value is daemon-owned (rendezvous and live
/// remeasure); nothing trusts writer-supplied channel, publication, or facts.
///
/// # Errors
///
/// Fails closed when the authenticated frame disagrees with the exact
/// retained process or carries a zero kill key.
type _KeepStartupImport = ();
#[expect(
    dead_code,
    reason = "receive_linux_writer_evidence stays the tested evidence core"
)]
pub(crate) fn receive_linux_writer_evidence(
    transport: UnixStream,
    transfer_authority: ProviderCredentialBrokerTransferAuthority,
    expected_release_tuple: [u8; 32],
    expected_channel: [u8; 32],
    expected_publication_public_key: [u8; 32],
    live_start_identity: [u8; 32],
    live_image_digest: [u8; 32],
) -> Result<[u8; 32], Error> {
    let (measurements, _rotated_authority) = receive_daemon_owned_writer_measurements(
        transport,
        transfer_authority,
        expected_release_tuple,
        expected_channel,
        expected_publication_public_key,
    )
    .map_err(|_| Error::AccessDenied)?;
    measurements
        .verified_linux_kill_public_key(live_start_identity, live_image_digest)
        .ok_or(Error::AccessDenied)
}

const fn crate_sanitize(result: Result<[u8; 32], Error>) -> Result<[u8; 32], Error> {
    result
}
