use std::{
    io::{Read as _, Write as _},
    os::unix::net::UnixStream,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use runne_api::ProviderCredentialEnrollmentHostError as Error;
use runne_provider::{
    CredentialBindingDigest, CredentialBrokerFrame, CredentialBrokerFrameCodec,
    CredentialEnrollmentAuthorityPair, CredentialSecretClaimOffer, CredentialWriterAuthorityPair,
    CredentialWriterCommandScopeV1, CredentialWriterQualifiedAckCodec,
    CredentialWriterQualifiedAckSigner, CredentialWriterQualifiedPreludeCodec,
    CredentialWriterSessionAttestationV2Codec, PendingCredentialIssueTicketV1,
};
use zeroize::Zeroizing;

use super::connected_attestation::claims;
use crate::application::provider_credential_enrollment::broker::{
    CredentialBrokerChannel, QualifiedCredentialBrokerChannel, QualifiedIssueTransmission,
};
use crate::protected_activation::control_v3::initial_exchange::session_test_support::ConnectedQualificationReceiver;
use runne_provider::daemon_credential_publication::CredentialWriterSessionAttestationSigner;

pub(super) struct UnixQualifiedChannel {
    stream: UnixStream,
    binding: CredentialBindingDigest,
    signer: Option<CredentialWriterSessionAttestationSigner>,
    prelude: Option<(
        runne_provider::CredentialWriterQualifiedPreludeSigner,
        Vec<u8>,
    )>,
    ack: Option<CredentialWriterQualifiedAckSigner>,
    publication:
        Option<runne_provider::daemon_credential_publication::CredentialSecretPublicationSigner>,
    events: Arc<Mutex<Vec<&'static str>>>,
    original_ticket_digest: Option<[u8; 32]>,
    acknowledged: bool,
    mutate_admission: bool,
}

pub(super) struct Receiver(JoinHandle<Result<(), runne_provider::CredentialEnrollmentError>>);

pub(super) struct MockService {
    events: Arc<Mutex<Vec<&'static str>>>,
}

impl UnixQualifiedChannel {
    pub(super) fn new(
        receiver: ConnectedQualificationReceiver,
        mutate_admission: bool,
    ) -> (Self, Receiver, MockService) {
        let binding = [21; 32];
        let signer = CredentialWriterSessionAttestationSigner::generate(binding).unwrap();
        let public_key = signer.public_key();
        let events = Arc::new(Mutex::new(Vec::new()));
        let receiver_events = Arc::clone(&events);
        let (stream, mut receiver_stream) = UnixStream::pair().unwrap();
        let (release, verifier) = receiver.into_parts();
        let receiver = Receiver(std::thread::spawn(move || {
            let attestation = CredentialWriterSessionAttestationV2Codec::read_from(
                &mut receiver_stream,
                public_key,
            )
            .unwrap();
            let pending = PendingCredentialIssueTicketV1::read_from(&mut receiver_stream)
                .unwrap()
                .with_qualified_attestation(attestation)
                .bind_test_verified_qualification_release(&release, verifier)
                .unwrap();
            let (_, measurements) = CredentialEnrollmentAuthorityPair::new().split();
            let channel = measurements.broker_channel_binding(binding).unwrap();
            let (issuer, _) = CredentialWriterAuthorityPair::new().split();
            let result = pending
                .claim_on(
                    &mut receiver_stream,
                    &issuer,
                    &channel,
                    runne_provider::CredentialSecretInputPresence::Present,
                    CredentialWriterCommandScopeV1::D1_1A,
                )
                .map(|_| ());
            if result.is_ok() {
                receiver_events.lock().unwrap().push("receiver-accepted");
            }
            result
        }));
        (
            Self {
                stream,
                binding: CredentialBindingDigest::from_measured(binding).unwrap(),
                signer: Some(signer),
                prelude: None,
                ack: None,
                publication: None,
                events: Arc::clone(&events),
                original_ticket_digest: None,
                acknowledged: false,
                mutate_admission,
            },
            receiver,
            MockService { events },
        )
    }

    pub(super) fn join(receiver: Receiver, accepted: bool) {
        assert_eq!(receiver.0.join().unwrap().is_ok(), accepted);
    }

    pub(super) fn events(&self) -> Vec<&'static str> {
        self.events.lock().unwrap().clone()
    }

    pub(super) const fn original_ticket_digest(&self) -> Option<[u8; 32]> {
        self.original_ticket_digest
    }

    pub(super) const fn acknowledged(&self) -> bool {
        self.acknowledged
    }
}

impl CredentialBrokerChannel for UnixQualifiedChannel {
    fn binding_digest(&self) -> CredentialBindingDigest {
        self.binding
    }

    fn send_issue(
        &mut self,
        _: &runne_provider::IssuedCredentialTicketAttempt,
        _: CredentialBrokerFrame,
    ) -> Result<(), Error> {
        Err(Error::AccessDenied)
    }

    fn send(&mut self, frame: Zeroizing<Vec<u8>>) -> Result<(), Error> {
        let frame = CredentialBrokerFrameCodec::decode(&frame).map_err(|_| Error::AccessDenied)?;
        CredentialBrokerFrameCodec::write_to(&mut self.stream, frame)
            .map_err(|_| Error::Unavailable)?;
        self.events.lock().unwrap().push("claim-accepted");
        Ok(())
    }

    fn receive(&mut self) -> Result<Zeroizing<Vec<u8>>, Error> {
        let frame = CredentialBrokerFrameCodec::read_from(&mut self.stream)
            .map_err(|_| Error::AccessDenied)?;
        self.events.lock().unwrap().push("claim");
        CredentialBrokerFrameCodec::encode(frame)
            .map(Zeroizing::new)
            .map_err(|_| Error::AccessDenied)
    }

    fn sign_publication(
        &mut self,
        offer: CredentialSecretClaimOffer,
    ) -> Result<runne_provider::CredentialSecretPublication, Error> {
        let signer = self.publication.take().ok_or(Error::AccessDenied)?;
        let publication = signer
            .sign(offer, self.binding)
            .map_err(|_| Error::AccessDenied)?;
        self.events.lock().unwrap().push("publication");
        Ok(publication)
    }
}

impl QualifiedCredentialBrokerChannel for UnixQualifiedChannel {
    fn send_qualified_issue(&mut self, issue: QualifiedIssueTransmission) -> Result<(), Error> {
        let (receipt, frame, launch_generation, admission) = issue.into_signing_parts();
        let (context_sha256, ticket_sha256, bundle) = admission.into_qualified_signing_material();
        let CredentialBrokerFrame::IssueTicket { ticket, .. } = &frame else {
            return Err(Error::AccessDenied);
        };
        self.original_ticket_digest = Some(ticket.binding_digest().as_bytes());
        let signer = self.signer.take().ok_or(Error::AccessDenied)?;
        let (attestation, prelude) = signer
            .sign_qualified(
                claims(&frame, &receipt),
                launch_generation,
                context_sha256,
                ticket_sha256,
            )
            .map_err(|_| Error::AccessDenied)?;
        self.stream
            .write_all(&CredentialWriterSessionAttestationV2Codec::encode(
                &attestation,
            ))
            .map_err(|_| Error::Unavailable)?;
        CredentialBrokerFrameCodec::write_to(&mut self.stream, frame)
            .map_err(|_| Error::Unavailable)?;
        self.prelude = Some((prelude, bundle));
        self.events.lock().unwrap().push("issue");
        Ok(())
    }

    fn send_qualified_prelude(&mut self) -> Result<(), Error> {
        let (signer, bundle) = self.prelude.take().ok_or(Error::AccessDenied)?;
        let mut bundle = bundle;
        if self.mutate_admission {
            bundle[17] ^= 1;
        }
        let (prelude, signer) = signer
            .sign_prelude(bundle)
            .map_err(|_| Error::AccessDenied)?;
        self.stream
            .write_all(
                &CredentialWriterQualifiedPreludeCodec::encode(&prelude)
                    .map_err(|_| Error::AccessDenied)?,
            )
            .map_err(|_| Error::Unavailable)?;
        self.prelude = None;
        self.events.lock().unwrap().push("prelude");
        self.ack = Some(signer);
        Ok(())
    }

    fn receive_qualified_ack(&mut self) -> Result<(), Error> {
        let signer = self.ack.take().ok_or(Error::AccessDenied)?;
        self.publication = Some(
            signer
                .accept_ack(read_ack(&mut self.stream)?)
                .map_err(|_| Error::AccessDenied)?,
        );
        self.acknowledged = true;
        self.events.lock().unwrap().push("ack");
        Ok(())
    }

    fn qualified_exchange_check(&mut self) -> Result<(), Error> {
        Ok(())
    }
}

impl super::super::QualifiedWriterService<UnixQualifiedChannel> for MockService {
    fn arm_and_handoff(
        &self,
        _: runne_provider::CredentialBrokerCommand,
        channel: &mut UnixQualifiedChannel,
    ) -> Result<(), Error> {
        if !channel.acknowledged() {
            return Err(Error::AccessDenied);
        }
        let mut events = self.events.lock().unwrap();
        events.push("service-arm");
        events.push("service-handoff");
        Ok(())
    }
}

fn read_ack(
    stream: &mut UnixStream,
) -> Result<runne_provider::CredentialWriterQualifiedAckV1, Error> {
    let mut bytes = [0; CredentialWriterQualifiedAckCodec::BYTES];
    stream
        .read_exact(&mut bytes)
        .map_err(|_| Error::AccessDenied)?;
    CredentialWriterQualifiedAckCodec::decode(&bytes).map_err(|_| Error::AccessDenied)
}
