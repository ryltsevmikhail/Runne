impl ProtectedBundledRuntimeProcess {
    // The v3 renewal clock path is consumed only by the macOS continuous-clock
    // caller and the macOS-gated renewal suites; other hosts keep it compiled
    // (common protocol logic) and silence the platform-local dead-code lint.
#[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
    fn renew_v3_profile_with_clock<F>(
        &mut self,
        clock: F,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError>
    where
        F: FnOnce() -> Result<u64, ProtectedBundledRuntimeError>,
    {
        if self.graceful_requested {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let sequence = self
            .renewal_sequence
            .checked_add(1)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        if nonce == [0; 32] {
            return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                LaunchAuthorityError::RenewalUnavailable,
            ));
        }
        let mut request_started = false;
        let result = {
            let keys = &self.keys;
            let (channel, activation) = (&mut self.channel, &mut self.activation);
            let ProtectedProcessActivation::V3 {
                request,
                ready,
                owned,
            } = activation
            else {
                return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                    LaunchAuthorityError::RenewalUnavailable,
                ));
            };
            renew_v3_exchange(
                channel,
                request,
                ready,
                owned,
                sequence,
                nonce,
                &mut request_started,
                keys,
                clock,
            )
        };
        match result {
            Ok((profile, next_owned)) => {
                let ProtectedProcessActivation::V3 { owned, .. } = &mut self.activation else {
                    return Err(ProtectedBundledRuntimeError::InvalidState);
                };
                *owned = next_owned;
                self.renewal_sequence = sequence;
                Ok(profile)
            }
            Err(error) => {
                if request_started {
                    self.fence_ambiguous_v3_renewal();
                }
                Err(error)
            }
        }
    }

    #[cfg(test)]
#[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
    fn renew_v3_profile_for_test<F>(
        &mut self,
        clock: F,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError>
    where
        F: FnOnce() -> Result<u64, ProtectedBundledRuntimeError>,
    {
        self.renew_v3_profile_with_clock(clock)
    }

#[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
    fn fence_ambiguous_v3_renewal(&mut self) {
        self.graceful_requested = true;
        self.graceful_acknowledged = false;
        #[cfg(unix)]
        {
            use std::net::Shutdown;
            let _ = self.channel.shutdown(Shutdown::Both);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[allow(clippy::too_many_arguments)] // The exact V3 authority tuple stays explicit.
#[cfg_attr(not(all(target_os = "macos", target_arch = "aarch64")), allow(dead_code))]
fn renew_v3_exchange<F>(
    channel: &mut ProtectedChannel,
    request: &runne_api::ProtectedCredentialEnrollmentLaunchRequestV3,
    ready: &runne_api::ProtectedCredentialEnrollmentReadyV3,
    owned: &runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    sequence: u64,
    mut nonce: [u8; 32],
    request_started: &mut bool,
    keys: &ProtectedActivationKeys,
    clock: F,
) -> Result<
    (
        ProtectedBundledRuntimeProfile,
        runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ),
    ProtectedBundledRuntimeError,
>
where
    F: FnOnce() -> Result<u64, ProtectedBundledRuntimeError>,
{
    let mut renewal = runne_api::ProtectedCredentialEnrollmentRenewRequestV3::new(
        owned.clone(),
        sequence,
        nonce,
    )?;
    nonce.fill(0);
    renewal.sign(keys);
    let frame = Zeroizing::new(
        renewal
            .encode_frame()
            .map_err(|_| LaunchAuthorityError::InvalidContract)?,
    );
    // A failed write may have delivered a prefix to the daemon; once this
    // call starts, the current owned state is no longer safely reusable.
    *request_started = true;
    write_frame(channel, &frame)?;
    let ticket_frame = Zeroizing::new(read_frame(channel)?);
    let ticket = runne_api::ProtectedCredentialEnrollmentRenewTicketV3::decode_frame(&ticket_frame)
        .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
    // Read completion precedes the shared boot-domain time sample. A suspended
    // desktop cannot reuse a ticket whose continuous-time window has elapsed.
    let now_ticket_millis = clock()?;
    let last_sequence = sequence
        .checked_sub(1)
        .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
    let profile = ProtectedBundledRuntimeProfile::from_renewal_v3(
        ready,
        request,
        owned,
        &renewal,
        &ticket,
        now_ticket_millis,
        last_sequence,
        keys,
    )?;
    let next_owned = profile.enrollment_owned_launch().cloned().ok_or(
        ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::OwnershipMismatch),
    )?;
    Ok((profile, next_owned))
}
