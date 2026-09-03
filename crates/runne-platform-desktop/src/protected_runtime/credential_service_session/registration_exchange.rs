use std::time::Instant;

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
    REGISTRATION_TIMEOUT, RegisteredCredentialServiceSession, unix_millis,
};

pub(in crate::protected_runtime) async fn register_credential_service_session_with_port(
    port: &impl CredentialServiceDesktopPort,
    authenticator: CredentialServiceSessionAuthenticator,
    facts: CredentialServiceRegistrationFacts,
) -> Result<RegisteredCredentialServiceSession, CredentialServiceSessionRegistrationError> {
    let request = CredentialServiceRequest::RegistrationChallenge;
    let reply_context = request.context();
    let frame = CredentialServiceProtocolCodec::encode_request(request)
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let request = CredentialServiceDesktopRequest::from_zeroizing(frame.into_transport_bytes())
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidFacts)?;
    let reply = port
        .challenge(request, call_context()?)
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
        .register(request, call_context()?)
        .await
        .map_err(|_| CredentialServiceSessionRegistrationError::Transport)?;
    let now = unix_millis()?;
    let acknowledgement = reply
        .with_bytes(|bytes| authenticator.decode_and_verify_ack_for(bytes, &binding, now))
        .map_err(|_| CredentialServiceSessionRegistrationError::InvalidReply)?;
    Ok(RegisteredCredentialServiceSession {
        claim,
        acknowledgement,
        configuration: None,
    })
}

fn call_context() -> Result<CredentialServiceCallContext, CredentialServiceSessionRegistrationError>
{
    let deadline = Instant::now()
        .checked_add(REGISTRATION_TIMEOUT)
        .ok_or(CredentialServiceSessionRegistrationError::InvalidFacts)?;
    Ok(CredentialServiceCallContext::new(
        deadline,
        CredentialServiceCancellation::new(),
    ))
}
