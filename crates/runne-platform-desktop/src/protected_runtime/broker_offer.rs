use super::{ProtectedBundledRuntimeError, ProtectedChannel, read_frame, write_frame};
use runne_api::{
    CredentialBrokerTransferAuthenticator, ProviderCredentialBrokerHandoffContext,
    ProviderCredentialBrokerHandoffFrame,
};

pub(super) fn exchange(
    channel: &mut ProtectedChannel,
    context: &ProviderCredentialBrokerHandoffContext,
    authenticator: &CredentialBrokerTransferAuthenticator,
    purpose: u8,
    mut clock: impl FnMut() -> Result<u64, ProtectedBundledRuntimeError>,
) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
    let nonce = send(channel, context, authenticator, purpose, &mut clock)?;
    receive(
        channel,
        context,
        authenticator,
        ProviderCredentialBrokerHandoffFrame::PHASE_READY,
        purpose,
        nonce,
        clock,
    )?;
    Ok(nonce)
}

pub(super) fn send(
    channel: &mut ProtectedChannel,
    context: &ProviderCredentialBrokerHandoffContext,
    authenticator: &CredentialBrokerTransferAuthenticator,
    purpose: u8,
    mut clock: impl FnMut() -> Result<u64, ProtectedBundledRuntimeError>,
) -> Result<[u8; 16], ProtectedBundledRuntimeError> {
    let now = clock()?;
    let expires = now
        .checked_add(30_000)
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let mut nonce = [0; 16];
    rand::RngCore::try_fill_bytes(&mut rand::rngs::OsRng, &mut nonce)
        .map_err(|_| ProtectedBundledRuntimeError::ProtectedChannelUnavailable)?;
    let offer = ProviderCredentialBrokerHandoffFrame::offer(
        context.clone(),
        purpose,
        now,
        expires,
        nonce,
        authenticator,
    )
    .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
    write_frame(channel, &offer.encode_frame())?;
    Ok(nonce)
}

pub(super) fn receive(
    channel: &mut ProtectedChannel,
    context: &ProviderCredentialBrokerHandoffContext,
    authenticator: &CredentialBrokerTransferAuthenticator,
    phase: u8,
    purpose: u8,
    nonce: [u8; 16],
    mut clock: impl FnMut() -> Result<u64, ProtectedBundledRuntimeError>,
) -> Result<(), ProtectedBundledRuntimeError> {
    let frame = read_frame(channel)?;
    let received_at = clock()?;
    ProviderCredentialBrokerHandoffFrame::decode_and_verify(
        &frame,
        authenticator,
        context,
        phase,
        purpose,
        nonce,
        received_at,
    )
    .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    Ok(())
}

#[cfg(test)]
mod tests;
