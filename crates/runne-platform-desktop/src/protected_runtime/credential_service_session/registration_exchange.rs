use std::time::Instant;

#[cfg(test)]
mod tests;

use runne_api::CredentialServiceSessionAuthenticator;
use runne_platform_ports::credential_service::{
    CredentialServiceCallContext, CredentialServiceCancellation, CredentialServiceDesktopPort,
    CredentialServiceDesktopRequest,
};
use runne_provider::{
    CredentialServiceProtocolCodec, CredentialServiceReply, CredentialServiceRequest,
};

use super::{
    CredentialServiceRegistrationFacts, CredentialServiceSessionRegistrationError,
    RegisteredCredentialServiceSession, unix_millis,
};

pub(in crate::protected_runtime) async fn register_credential_service_session_with_port(
    port: &impl CredentialServiceDesktopPort,
    authenticator: CredentialServiceSessionAuthenticator,
    facts: CredentialServiceRegistrationFacts,
) -> Result<RegisteredCredentialServiceSession, CredentialServiceSessionRegistrationError> {
    register_with_clock(port, authenticator, facts, unix_millis).await
}

pub(super) async fn register_with_clock(
    port: &impl CredentialServiceDesktopPort,
    authenticator: CredentialServiceSessionAuthenticator,
    facts: CredentialServiceRegistrationFacts,
    clock: impl Fn() -> Result<u64, CredentialServiceSessionRegistrationError>,
) -> Result<RegisteredCredentialServiceSession, CredentialServiceSessionRegistrationError> {
    let started = clock()?;
    let deadline = started
        .checked_add(5_000)
        .ok_or(CredentialServiceSessionRegistrationError::InvalidFacts)?
        .min(facts.expires_at_unix_millis)
        .min(facts.exchange_deadline.unwrap_or(u64::MAX));
    let request = CredentialServiceRequest::RegistrationChallenge;
    let reply_context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request)
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let request = CredentialServiceDesktopRequest::from_zeroizing(frame.into_transport_bytes())
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let reply = port
        .challenge(request, call_context(deadline, clock()?.max(started))?)
        .await
        .map_err(|_| CredentialServiceSessionRegistrationError::Transport)?;
    let reply = reply
        .with_bytes(|bytes| {
            CredentialServiceProtocolCodec::decode_desktop_reply(bytes, reply_context)
        })
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidReply)?;
    let CredentialServiceReply::RegistrationChallenge { epoch, nonce } = reply else {
        return Err(CredentialServiceSessionRegistrationError::InvalidReply);
    };
    let binding = facts.binding(epoch.as_bytes(), nonce)?;
    let claim = authenticator
        .authenticate_registration(binding.clone())
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let install = authenticator
        .registration_install(binding.clone())
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let request = CredentialServiceDesktopRequest::from_zeroizing(install.into_transport_bytes())
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let reply = port
        .register(request, call_context(deadline, clock()?.max(started))?)
        .await
        .map_err(|_| CredentialServiceSessionRegistrationError::Transport)?;
    let now = clock()?.max(started);
    if now >= deadline {
        return Err(CredentialServiceSessionRegistrationError::InvalidReply);
    }
    let acknowledgement = reply
        .with_bytes(|bytes| authenticator.decode_and_verify_ack_for(bytes, &binding, now))
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidReply)?;
    Ok(RegisteredCredentialServiceSession {
        exchange_deadline: Some(deadline),
        claim,
        acknowledgement,
        configuration: None,
    })
}

fn call_context(
    deadline: u64,
    now: u64,
) -> Result<CredentialServiceCallContext, CredentialServiceSessionRegistrationError> {
    let remaining = deadline
        .checked_sub(now)
        .filter(|value| *value > 0)
        .ok_or(CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let deadline = Instant::now()
        .checked_add(std::time::Duration::from_millis(remaining))
        .ok_or(CredentialServiceSessionRegistrationError::InvalidFacts)?;
    Ok(CredentialServiceCallContext::new(
        deadline,
        CredentialServiceCancellation::new(),
    ))
}
