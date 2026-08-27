use runne_api::ProviderCredentialEnrollmentHostError;
use runne_platform_desktop::provider_credential_broker::{
    UnixReceivedWriterControl, WriterProcessEvidence,
};
use runne_provider::{CredentialBrokerFrame, CredentialBrokerFrameCodec};
use zeroize::Zeroizing;

use super::CredentialBrokerChannel;

/// Daemon-owned half of a control socket accepted by the native handoff.
///
/// Construction consumes [`UnixReceivedWriterControl`], so ordinary daemon
/// callers cannot supply a pathname, raw descriptor, or serializable handle.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 protected control dispatcher constructs this only after its native prompt and handoff are composed"
    )
)]
pub(super) struct UnixCredentialBrokerChannel {
    control: std::os::unix::net::UnixStream,
    _evidence: WriterProcessEvidence,
    received_frames: u8,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Task 11 protected control dispatcher consumes this exact one-shot channel"
    )
)]
impl UnixCredentialBrokerChannel {
    pub(super) fn from_authenticated_handoff(handoff: UnixReceivedWriterControl) -> Self {
        let (control, evidence) = handoff.into_parts();
        Self {
            control,
            _evidence: evidence,
            received_frames: 0,
        }
    }

    /// Sends one canonical daemon-to-writer frame.
    pub(super) fn send_frame(
        &mut self,
        frame: CredentialBrokerFrame,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        CredentialBrokerFrameCodec::write_to(&mut self.control, frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::Unavailable)
    }

    /// Receives a bounded writer response in the claim/effect sequence.
    ///
    /// The protocol admits a claim followed by one possible-effect diagnostic;
    /// a third writer frame is always rejected before it is read.
    pub(super) fn receive_once(
        &mut self,
    ) -> Result<CredentialBrokerFrame, ProviderCredentialEnrollmentHostError> {
        if self.received_frames >= 2 {
            return Err(ProviderCredentialEnrollmentHostError::AccessDenied);
        }
        self.received_frames += 1;
        CredentialBrokerFrameCodec::read_from(&mut self.control)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

impl CredentialBrokerChannel for UnixCredentialBrokerChannel {
    fn send(
        &mut self,
        frame: Zeroizing<Vec<u8>>,
    ) -> Result<(), ProviderCredentialEnrollmentHostError> {
        let frame = CredentialBrokerFrameCodec::decode(&frame)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)?;
        self.send_frame(frame)
    }

    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, ProviderCredentialEnrollmentHostError> {
        let frame = self.receive_once()?;
        CredentialBrokerFrameCodec::encode(frame)
            .map(Zeroizing::new)
            .map_err(|_| ProviderCredentialEnrollmentHostError::AccessDenied)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use runne_api::{CredentialBrokerTransferAuthenticator, LaunchSecret};
    use runne_platform_desktop::provider_credential_broker::{
        RetainedWriterProcess, receive_unix_writer_control, spawn_unix_writer,
        transfer_unix_writer_control,
    };
    use runne_platform_ports::provider_credential_broker::{
        VerifiedWriterArtifact, VerifiedWriterLaunchSpec,
    };
    use runne_provider::{
        CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialOperationId,
        CredentialTicketAttempt, RawCredentialTicket,
    };

    use super::UnixCredentialBrokerChannel;

    #[test]
    fn authenticated_handoff_channel_exchanges_one_exact_broker_frame() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("writer-fixture");
        std::fs::write(
            &executable,
            "#!/bin/sh\n[ \"$1\" = \"__provider-credential-broker-v1\" ] || exit 11\ndd bs=1 count=58 >&2 2>/dev/null\n",
        )
        .unwrap();
        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        let artifact = VerifiedWriterArtifact::new(executable, [1; 32], [2; 32]).unwrap();
        let (mut endpoints, mut process, evidence) =
            spawn_unix_writer(&VerifiedWriterLaunchSpec::new(artifact)).unwrap();
        let (mut sender, mut receiver) = std::os::unix::net::UnixStream::pair().unwrap();
        let keys = LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys();
        let sender_authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let receiver_authenticator =
            CredentialBrokerTransferAuthenticator::from_protected_activation(&keys);
        let binding = evidence.channel_binding();
        let receiver_thread = std::thread::spawn(move || {
            receive_unix_writer_control(&mut receiver, &receiver_authenticator, binding)
        });
        transfer_unix_writer_control(
            &mut sender,
            &mut endpoints,
            &sender_authenticator,
            &evidence,
        )
        .unwrap();
        let received = receiver_thread.join().unwrap().unwrap();
        let mut channel = UnixCredentialBrokerChannel::from_authenticated_handoff(received);
        let expected = CredentialBrokerFrameCodec::encode(CredentialBrokerFrame::IssueTicket {
            operation_id: CredentialOperationId::from_bytes([3; 16]).unwrap(),
            attempt: CredentialTicketAttempt::new(1).unwrap(),
            ticket: RawCredentialTicket::generate().unwrap(),
        })
        .unwrap();

        channel
            .send_frame(CredentialBrokerFrameCodec::decode(&expected).unwrap())
            .unwrap();
        let echoed = channel.receive_once().unwrap();
        assert_eq!(
            CredentialBrokerFrameCodec::encode(echoed).unwrap(),
            expected
        );
        assert!(matches!(
            channel.receive_once(),
            Err(runne_api::ProviderCredentialEnrollmentHostError::AccessDenied)
        ));
        drop(channel);
        process.reap_retained_child().unwrap();
    }
}
