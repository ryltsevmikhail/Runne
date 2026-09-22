//! SELF-CONTAINED Linux authority entry: the ONLY public way a Linux writer
//! session is created. Everything is adopted from the ACTUAL inherited
//! descriptors and the proof-verified startup exchange — no caller-supplied
//! sockets, keys, digests, or paths exist anywhere in the signature.

use std::io::Read as _;
use std::os::fd::OwnedFd;
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use runne_provider::{
    CredentialBindingDigest, CredentialEnrollmentAuthorityPair,
    CredentialWriterSessionAttestationCodec, CredentialWriterSessionAttestationV2Codec,
    LinuxWriterStartup, PendingCredentialIssueTicketV1, linux_writer_self_measurements,
    respond_linux_writer_startup,
};

use super::AuthenticatedProviderCredentialWriterSession;
use super::linux_verifier::{
    LinuxWriterSessionExpectations, LinuxWriterSessionResources, authenticate_linux_writer_session,
};
mod reader;

impl AuthenticatedProviderCredentialWriterSession {
    /// Adopts the inherited STARTUP (stdout) and CONTROL (stdin) sockets,
    /// completes the proof-verified startup exchange, reads the daemon-signed
    /// V1 or qualification-required V2 attestation and `IssueTicket` frame,
    /// derives every expected value from the retained startup state, and
    /// mints this closed session with an already-bound ticket.
    ///
    /// # Errors
    ///
    /// Fails closed on wrong descriptor types, startup proof failure,
    /// signature/freshness/channel/handoff/tuple/ticket mismatch, or EOF —
    /// before any effect capability exists.
    pub fn receive_linux_authenticated_writer() -> Result<Self, &'static str> {
        let startup_transport = adopt_inherited_socket(&std::io::stdout())
            .map_err(|_| "startup transport is not an inherited socket")?;
        let startup =
            respond_linux_writer_startup(startup_transport).map_err(|_| "startup proof denied")?;
        let (live_start, live_image) =
            linux_writer_self_measurements().map_err(|_| "live self-measurement failed")?;
        let mut control = adopt_inherited_socket(&std::io::stdin())
            .map_err(|_| "control transport is not an inherited socket")?;
        let (attestation_bytes, bound_ticket) = read_control(&startup, &mut control)?;
        let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
        let channel = measurements
            .broker_channel_binding(startup.channel_binding)
            .map_err(|_| "channel digest")?;
        let handoff = CredentialBindingDigest::from_measured(startup.channel_binding)
            .map_err(|_| "handoff digest")?;
        let reader_path = reader::verified_reader_path(
            &control,
            &attestation_bytes,
            startup.publication_public_key,
            live_start,
            live_image,
        )?;
        authenticate_linux_writer_session(
            LinuxWriterSessionExpectations {
                attestation_bytes: &attestation_bytes,
                retained_publication_key: startup.publication_public_key,
                retained_channel_binding: &channel,
                retained_handoff_sha256: handoff.as_bytes(),
                live_start_sha256: live_start,
                live_image_sha256: live_image,
                release_tuple_sha256: startup.release_tuple,
                ticket: bound_ticket,
            },
            LinuxWriterSessionResources {
                channel_binding: channel.clone(),
                control,
                writer_path: PathBuf::from("/proc/self/exe"),
                reader_path,
            },
        )
    }
}

fn read_control(
    startup: &LinuxWriterStartup,
    control: &mut UnixStream,
) -> Result<(Vec<u8>, PendingCredentialIssueTicketV1), &'static str> {
    // Keep one unbuffered socket through entry and claim. Stdin's buffer can
    // otherwise retain a coalesced prelude/ACK that the later socket cannot see.
    let mut version = [0];
    control
        .read_exact(&mut version)
        .map_err(|_| "control version denied")?;
    let length = match version[0] {
        1 => CredentialWriterSessionAttestationCodec::BYTES,
        2 => CredentialWriterSessionAttestationV2Codec::BYTES,
        _ => return Err("control version denied"),
    };
    let mut bytes = vec![0; length];
    bytes[0] = version[0];
    control
        .read_exact(&mut bytes[1..])
        .map_err(|_| "control attestation denied")?;
    // Select the signed format once. An invalid V2 must never retry as V1.
    let qualified = match version[0] {
        1 => {
            CredentialWriterSessionAttestationCodec::decode_and_verify(
                &bytes,
                startup.publication_public_key,
            )
            .map_err(|_| "control attestation denied")?;
            None
        }
        2 => Some(
            CredentialWriterSessionAttestationV2Codec::decode_and_verify(
                &bytes,
                startup.publication_public_key,
            )
            .map_err(|_| "control attestation denied")?,
        ),
        _ => unreachable!("closed version match"),
    };
    let ticket =
        PendingCredentialIssueTicketV1::read_from(control).map_err(|_| "control ticket denied")?;
    let ticket = match qualified {
        Some(attestation) => startup
            .bind_verified_control(&attestation, &bytes, ticket)
            .map_err(|_| "control binding denied")?,
        None => ticket,
    };
    Ok((bytes, ticket))
}

fn adopt_inherited_socket<T>(handle: &T) -> Result<UnixStream, &'static str>
where
    T: std::io::IsTerminal + std::os::fd::AsFd,
{
    if handle.is_terminal() {
        return Err("descriptor is a terminal");
    }
    let owned = handle
        .as_fd()
        .try_clone_to_owned()
        .map_err(|_| "descriptor adoption")?;
    let file = std::fs::File::from(owned);
    if !file
        .metadata()
        .map_err(|_| "descriptor stat")?
        .file_type()
        .is_socket()
    {
        return Err("descriptor is not a socket");
    }
    Ok(UnixStream::from(OwnedFd::from(file)))
}

#[cfg(test)]
mod descriptor_tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn adoption_preserves_the_live_socket_and_rejects_regular_files() {
        let (socket, mut peer) = UnixStream::pair().unwrap();
        let original = std::fs::File::from(OwnedFd::from(socket));
        let mut adopted = adopt_inherited_socket(&original).unwrap();
        drop(original);
        peer.write_all(b"private").unwrap();
        let mut bytes = [0; 7];
        adopted.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"private");
        let regular = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
        assert!(adopt_inherited_socket(&regular).is_err());
    }
}
