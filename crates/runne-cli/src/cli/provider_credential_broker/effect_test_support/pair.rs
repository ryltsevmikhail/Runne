use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};

use runne_provider::{
    CredentialOperationAction, CredentialSecretInputPresence, CredentialWriterAuthorityPair,
};
use runne_secure_store::BrokeredProviderCredentialWriter;

use super::{
    EffectCall, FakeWriter, claim_writer_authorization_with_parts, command, endpoint,
};
use super::super::pair::AuthorizedPairWriterControl;

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

fn pair_authorized_with_control(
    create_succeeds: bool,
    fail_after_claim: bool,
) -> PairFixture {
    let command = command(CredentialOperationAction::Pair);
    let (control, channel, ticket, written) = endpoint(&command, fail_after_claim);
    let calls = Arc::new(Mutex::new(Vec::new()));
    let writer: Arc<dyn BrokeredProviderCredentialWriter> = Arc::new(FakeWriter {
        calls: calls.clone(),
        create_succeeds,
    });
    let (issuer, _) = CredentialWriterAuthorityPair::new().split();
    let claimed = claim_writer_authorization_with_parts(
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
    bytes[..2].copy_from_slice(&[
        runne_provider::CredentialSecretEnvelopeCodec::VERSION,
        2,
    ]);
    bytes[2..18].copy_from_slice(&command.operation_id().as_bytes());
    bytes[18..26].copy_from_slice(&command.ticket_attempt().get().to_be_bytes());
    bytes[26..58].fill(13);
    bytes[58..90].fill(14);
    bytes[90..122].fill(15);
    bytes[122..124].copy_from_slice(&1_u16.to_be_bytes());
    bytes
}
