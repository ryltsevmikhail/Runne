use std::os::unix::net::UnixStream;
use std::time::Duration;

use rand::{RngCore, rngs::OsRng};
#[cfg(feature = "desktop-protected")]
use runne_api::CredentialBrokerTransferAuthenticator;
use runne_api::ProviderCredentialEnrollmentHostError;

const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(30);

/// Daemon-created halves of one pending writer-control rendezvous.
///
/// Tauri receives only the writer endpoint through the authenticated protected
/// control transfer. It never creates this socketpair or reads broker frames.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected control dispatcher creates this before writer handoff"
    )
)]
pub(super) struct DaemonOwnedUnixBrokerRendezvous {
    daemon: Option<UnixStream>,
    writer: Option<UnixStream>,
    channel_binding: [u8; 32],
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the protected control dispatcher consumes each endpoint exactly once"
    )
)]
impl DaemonOwnedUnixBrokerRendezvous {
    /// Creates a fresh socketpair owned by the daemon process.
    pub(super) fn create() -> Result<Self, ProviderCredentialEnrollmentHostError> {
        let (daemon, writer) =
            UnixStream::pair().map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        configure(&daemon)?;
        configure(&writer)?;
        let mut channel_binding = [0; 32];
        OsRng
            .try_fill_bytes(&mut channel_binding)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)?;
        if channel_binding == [0; 32] {
            return Err(ProviderCredentialEnrollmentHostError::Unavailable);
        }
        Ok(Self {
            daemon: Some(daemon),
            writer: Some(writer),
            channel_binding,
        })
    }

    /// Returns the daemon-generated binding for the exact writer channel.
    #[must_use]
    pub(super) const fn channel_binding(&self) -> [u8; 32] {
        self.channel_binding
    }

    /// Moves the daemon endpoint into the post-handoff broker only once.
    pub(super) fn take_daemon_endpoint(
        &mut self,
    ) -> Result<UnixStream, ProviderCredentialEnrollmentHostError> {
        self.daemon
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    /// Moves the writer endpoint into the authenticated Tauri descriptor transfer once.
    pub(super) fn take_writer_endpoint(
        &mut self,
    ) -> Result<UnixStream, ProviderCredentialEnrollmentHostError> {
        self.writer
            .take()
            .ok_or(ProviderCredentialEnrollmentHostError::AccessDenied)
    }

    /// Sends the writer endpoint only through the authenticated protected control transport.
    #[cfg(feature = "desktop-protected")]
    pub(super) fn handoff_writer_endpoint(
        &mut self,
        transport: &mut UnixStream,
        authenticator: &CredentialBrokerTransferAuthenticator,
    ) -> Result<[u8; 32], ProviderCredentialEnrollmentHostError> {
        let binding = self.channel_binding;
        let writer = self.take_writer_endpoint()?;
        runne_platform_desktop::provider_credential_broker::send_daemon_owned_writer_endpoint(
            transport,
            writer,
            authenticator,
            binding,
        )
        .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        Ok(binding)
    }
}

fn configure(stream: &UnixStream) -> Result<(), ProviderCredentialEnrollmentHostError> {
    stream
        .set_read_timeout(Some(RENDEZVOUS_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(RENDEZVOUS_TIMEOUT)))
        .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn daemon_owned_rendezvous_moves_each_endpoint_once_and_binds_the_pair() {
        let mut rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
        assert_ne!(rendezvous.channel_binding(), [0; 32]);
        let mut daemon = rendezvous.take_daemon_endpoint().unwrap();
        let mut writer = rendezvous.take_writer_endpoint().unwrap();
        assert!(matches!(
            rendezvous.take_daemon_endpoint(),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
        assert!(matches!(
            rendezvous.take_writer_endpoint(),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));

        writer.write_all(b"claim").unwrap();
        let mut frame = [0; 5];
        daemon.read_exact(&mut frame).unwrap();
        assert_eq!(frame, *b"claim");
    }
}

#[cfg(all(test, feature = "desktop-protected"))]
mod protected_tests {
    use runne_api::LaunchSecret;

    use super::*;

    #[test]
    fn protected_handoff_moves_only_the_daemon_created_writer_endpoint() {
        let mut rendezvous = DaemonOwnedUnixBrokerRendezvous::create().unwrap();
        let expected = rendezvous.channel_binding();
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
        let sender_authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let receiver_authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let receiver_thread = std::thread::spawn(move || {
            runne_platform_desktop::provider_credential_broker::receive_daemon_owned_writer_endpoint(
                &mut receiver,
                &receiver_authenticator,
                expected,
            )
        });

        assert_eq!(
            rendezvous
                .handoff_writer_endpoint(&mut sender, &sender_authenticator)
                .unwrap(),
            expected
        );
        assert_eq!(
            receiver_thread.join().unwrap().unwrap().channel_binding(),
            expected
        );
        assert!(matches!(
            rendezvous.handoff_writer_endpoint(&mut sender, &sender_authenticator),
            Err(ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
    }
}
