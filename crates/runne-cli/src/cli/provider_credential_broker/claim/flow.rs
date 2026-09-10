use super::{
    BrokerChannelBinding, BrokerControl, ClaimedWriterAuthorization, ClaimedWriterControl,
    CliError, CredentialBindingDigest, CredentialBrokerCommand, CredentialSecretInputPresence,
    CredentialWriterBrokerHandoffFrame, CredentialWriterClaimIssuer,
    CredentialWriterCommandKindV1, CredentialWriterCommandScopeV1,
    NativeProviderCredentialEffectRoute, PendingCredentialIssueTicketV1,
    PendingCredentialSecretOpening, Read, Write,
};
#[cfg(any(test, target_os = "macos"))]
use super::qualified_deadline;

type ClaimParts = (
    ClaimedWriterAuthorization,
    CredentialBrokerCommand,
    CredentialBindingDigest,
    CredentialWriterCommandKindV1,
    Option<PendingCredentialSecretOpening>,
);

#[cfg(target_os = "macos")]
pub(super) fn claim_socket(
    control: std::os::unix::net::UnixStream,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    effect_route: NativeProviderCredentialEffectRoute,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    if !ticket.is_qualified() {
        return claim_unbounded(control, channel, ticket, issuer, effect_route, secret_input);
    }
    let mut qualified = qualified_deadline::QualifiedSocketControl::new(control)
        .map_err(|_| CliError::CredentialOperation)?;
    let claim = claim_ticket(&mut qualified, ticket, issuer, &channel, secret_input)?;
    let control = qualified
        .finish()
        .map_err(|_| CliError::CredentialOperation)?;
    finish_claim(Box::new(control), channel, effect_route, claim)
}

#[cfg(test)]
pub fn claim_generic<C: Read + Write + 'static>(
    control: C,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    effect_route: NativeProviderCredentialEffectRoute,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    if !ticket.is_qualified() {
        return claim_unbounded(control, channel, ticket, issuer, effect_route, secret_input);
    }
    let mut qualified = qualified_deadline::QualifiedBrokerControl::new(control);
    let claim = claim_ticket(&mut qualified, ticket, issuer, &channel, secret_input)?;
    finish_claim(
        Box::new(
            qualified
                .finish()
                .map_err(|_| CliError::CredentialOperation)?,
        ),
        channel,
        effect_route,
        claim,
    )
}

#[cfg(any(test, target_os = "macos"))]
fn claim_unbounded<C: Read + Write + 'static>(
    mut control: C,
    channel: BrokerChannelBinding,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    effect_route: NativeProviderCredentialEffectRoute,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimedWriterControl, CliError> {
    let claim = claim_ticket(&mut control, ticket, issuer, &channel, secret_input)?;
    finish_claim(Box::new(control), channel, effect_route, claim)
}

fn claim_ticket<C: Read + Write>(
    control: &mut C,
    ticket: PendingCredentialIssueTicketV1,
    issuer: &CredentialWriterClaimIssuer,
    channel: &BrokerChannelBinding,
    secret_input: CredentialSecretInputPresence,
) -> Result<ClaimParts, CliError> {
    ticket
        .claim_on(
            control,
            issuer,
            channel,
            secret_input,
            CredentialWriterCommandScopeV1::D1_1A,
        )
        .map_err(|_| CliError::CredentialOperation)
}

fn finish_claim(
    mut control: Box<dyn BrokerControl>,
    channel: BrokerChannelBinding,
    effect_route: NativeProviderCredentialEffectRoute,
    claim: ClaimParts,
) -> Result<ClaimedWriterControl, CliError> {
    let (authorization, command, binding, command_kind, pending_pair_secret_opening) = claim;
    #[cfg(target_os = "macos")]
    let requires_service_handoff = matches!(
        &effect_route,
        NativeProviderCredentialEffectRoute::CredentialService { .. }
    ) && command_kind != CredentialWriterCommandKindV1::LegacySourceCleanup;
    #[cfg(not(target_os = "macos"))]
    let requires_service_handoff = false;
    let service_handoff = if requires_service_handoff {
        Some(
            CredentialWriterBrokerHandoffFrame::read_from(&mut control)
                .map_err(|_| CliError::CredentialOperation)?,
        )
    } else {
        None
    };
    Ok(ClaimedWriterControl {
        control,
        effect_route,
        authorization,
        command,
        binding,
        channel,
        command_kind,
        pending_pair_secret_opening,
        service_handoff,
    })
}
