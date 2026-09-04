use super::*;

pub(super) fn initial(
    channel: &mut ProtectedActivationChannel,
) -> Result<interleaved::RejoinFrames, LaunchAuthorityError> {
    Ok(interleaved::RejoinFrames {
        claim: channel.read_control_frame()?,
        acknowledgement: channel.read_control_frame()?,
        deferred: None,
    })
}

pub(super) fn receive(
    channel: &mut ProtectedActivationChannel,
    keys: &ProtectedActivationKeys,
    expected: &ExpectedCredentialServiceRegistration,
    minimum_time: u64,
    read: impl FnOnce(
        &mut ProtectedActivationChannel,
    ) -> Result<interleaved::RejoinFrames, LaunchAuthorityError>,
    clock: impl FnOnce() -> Result<u64, LaunchAuthorityError>,
) -> Result<RejoinedCredentialService, LaunchAuthorityError> {
    let frames = read(channel)?;
    let now = clock()?.max(minimum_time);
    let session = accept_registration_frames(
        keys,
        expected,
        registration_payload(&frames.claim)?,
        registration_payload(&frames.acknowledgement)?,
        now,
    )?;
    Ok(RejoinedCredentialService {
        session,
        deferred: frames.deferred,
    })
}

pub(super) fn now() -> Result<u64, LaunchAuthorityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| LaunchAuthorityError::InvalidContract)?
        .as_millis()
        .try_into()
        .map_err(|_| LaunchAuthorityError::InvalidContract)
}

#[cfg(test)]
mod tests;
