use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};

use runne_provider::{
    CredentialBrokerFrame, CredentialBrokerFrameCodec, CredentialOperationAction,
    CredentialSecretInputPresence, CredentialWriterAuthorityPair,
};
use runne_secure_store::BrokeredProviderCredentialWriter;

use super::super::pair::AuthorizedPairWriterControl;
use super::{
    ClaimFixture, EffectCall, FakeWriter, claim_writer_authorization_with_legacy_parts, command,
    endpoint,
};

pub struct PairFixture {
    pub authority: AuthorizedPairWriterControl,
    pub calls: Arc<Mutex<Vec<EffectCall>>>,
    pub written: Arc<Mutex<Vec<u8>>>,
}

pub fn pair_authorized(create_succeeds: bool) -> PairFixture {
    pair_authorized_with_control(create_succeeds, false)
}

pub fn pair_authorized_with_diagnostic_failure() -> PairFixture {
    pair_authorized_with_control(true, true)
}

pub fn pair_claimed_with_release(release: Option<CredentialBrokerFrame>) -> ClaimFixture {
    pair_claimed_with_release_result(release, false)
}

pub fn pair_claimed_successfully() -> ClaimFixture {
    pair_claimed_with_release_result(
        Some(CredentialBrokerFrame::NativeEffectRelease {
            operation_id: runne_provider::CredentialOperationId::from_bytes([21; 16])
                .expect("operation"),
            attempt: runne_provider::CredentialTicketAttempt::new(1).expect("attempt"),
            binding: runne_provider::CredentialBindingDigest::from_measured([13; 32])
                .expect("binding"),
        }),
        true,
    )
}

fn pair_claimed_with_release_result(
    release: Option<CredentialBrokerFrame>,
    create_succeeds: bool,
) -> ClaimFixture {
    let command = command(CredentialOperationAction::Pair);
    let (mut control, channel, ticket, written) = endpoint(&command, false);
    if let Some(release) = release {
        CredentialBrokerFrameCodec::write_to(control.input.get_mut(), release).expect("release");
    }
    let calls = Arc::new(Mutex::new(Vec::new()));
    let writer: Arc<dyn BrokeredProviderCredentialWriter> = Arc::new(FakeWriter {
        calls: calls.clone(),
        create_succeeds,
    });
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    let claimed = claim_writer_authorization_with_legacy_parts(
        control,
        channel,
        ticket,
        &issuer,
        writer,
        CredentialSecretInputPresence::Present,
    )
    .expect("pair claim");
    ClaimFixture {
        claimed,
        calls,
        written,
    }
}

pub fn pair_claimed() -> ClaimFixture {
    let command = command(CredentialOperationAction::Pair);
    pair_claimed_with_release(Some(CredentialBrokerFrame::NativeEffectRelease {
        operation_id: command.operation_id(),
        attempt: command.ticket_attempt(),
        binding: runne_provider::CredentialBindingDigest::from_measured([13; 32]).expect("binding"),
    }))
}

fn pair_authorized_with_control(create_succeeds: bool, fail_after_claim: bool) -> PairFixture {
    let command = command(CredentialOperationAction::Pair);
    let (mut control, channel, ticket, written) = endpoint(&command, fail_after_claim);
    CredentialBrokerFrameCodec::write_to(
        control.input.get_mut(),
        CredentialBrokerFrame::NativeEffectRelease {
            operation_id: command.operation_id(),
            attempt: command.ticket_attempt(),
            binding: runne_provider::CredentialBindingDigest::from_measured([13; 32])
                .expect("binding"),
        },
    )
    .expect("release");
    let calls = Arc::new(Mutex::new(Vec::new()));
    let writer: Arc<dyn BrokeredProviderCredentialWriter> = Arc::new(FakeWriter {
        calls: calls.clone(),
        create_succeeds,
    });
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    let claimed = claim_writer_authorization_with_legacy_parts(
        control,
        channel,
        ticket,
        &issuer,
        writer,
        CredentialSecretInputPresence::Present,
    )
    .expect("pair claim");
    let authority = claimed
        .read_pair_secret(&mut Cursor::new(encoded_pair_envelope(&command)))
        .expect("sealed pair source");
    PairFixture {
        authority,
        calls,
        written,
    }
}

fn encoded_pair_envelope(command: &runne_provider::CredentialBrokerCommand) -> Vec<u8> {
    let mut bytes = vec![0; 141];
    bytes[..2].copy_from_slice(&[runne_provider::CredentialSecretEnvelopeCodec::VERSION, 2]);
    bytes[2..18].copy_from_slice(&command.operation_id().as_bytes());
    bytes[18..26].copy_from_slice(&command.ticket_attempt().get().to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}
