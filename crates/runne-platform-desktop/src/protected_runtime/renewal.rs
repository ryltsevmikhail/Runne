impl ProtectedBundledRuntimeProcess {
    /// Rotates the protected HTTP session without reusing launch authority.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for stale ownership, replay, channel, or ticket proof failures.
    pub fn renew_profile(
        &mut self,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        {
            Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend)
        }
        #[cfg(any(unix, windows))]
        {
            if matches!(self.activation, ProtectedProcessActivation::V3 { .. }) {
                return self.renew_v3_for_platform();
            }
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
            let profile = match &mut self.activation {
                ProtectedProcessActivation::V1 {
                    request,
                    ready,
                    owned,
                } => {
                    let mut renewal = ProtectedRenewRequestV1::new(owned.clone(), sequence, nonce)?;
                    nonce.fill(0);
                    renewal.sign(&self.keys);
                    write_frame(
                        &mut self.channel,
                        &Zeroizing::new(
                            renewal
                                .encode_frame()
                                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                        ),
                    )?;
                    let ticket =
                        ProtectedRenewTicketV1::decode_frame(&read_frame(&mut self.channel)?)
                            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
                    ticket.verify_exact(&renewal, &self.keys)?;
                    let profile = ProtectedBundledRuntimeProfile::from_renewal(
                        ready, request, &renewal, &ticket, &self.keys,
                    )?;
                    *owned = ticket.next_owned_launch();
                    profile
                }
                ProtectedProcessActivation::V2 {
                    request,
                    ready,
                    owned,
                } => {
                    let mut renewal = ProtectedRenewRequestV2::new(owned.clone(), sequence, nonce)?;
                    nonce.fill(0);
                    renewal.sign(&self.keys);
                    write_frame(
                        &mut self.channel,
                        &Zeroizing::new(
                            renewal
                                .encode_frame()
                                .map_err(|_| LaunchAuthorityError::InvalidContract)?,
                        ),
                    )?;
                    let ticket =
                        ProtectedRenewTicketV2::decode_frame(&read_frame(&mut self.channel)?)
                            .map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
                    ticket.verify_exact(&renewal, &self.keys)?;
                    let profile = ProtectedBundledRuntimeProfile::from_renewal_v2(
                        ready, request, &renewal, &ticket, &self.keys,
                    )?;
                    *owned = ticket.next_owned_launch();
                    profile
                }
                ProtectedProcessActivation::V3 { .. } => {
                    return Err(ProtectedBundledRuntimeError::LaunchAuthority(
                        LaunchAuthorityError::RenewalUnavailable,
                    ))
                }
                #[cfg(feature = "test-support")]
                ProtectedProcessActivation::Test { .. } => {
                    return Err(ProtectedBundledRuntimeError::InvalidState)
                }
            };
            self.renewal_sequence = sequence;
            Ok(profile)
        }
    }

    /// Samples the shared ticket clock for the V3 renewal: macOS continuous
    /// time here, unix wall-clock milliseconds elsewhere (matching the
    /// daemon's `unix_wall_ticket_clock`).
    fn renew_v3_for_platform(
        &mut self,
    ) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        return self.renew_v3_profile_with_clock(|| {
            crate::MacOsContinuousClock::now_millis().map_err(|_| {
                ProtectedBundledRuntimeError::LaunchAuthority(
                    LaunchAuthorityError::RenewalUnavailable,
                )
            })
        });
        #[cfg(all(
            unix,
            not(all(target_os = "macos", target_arch = "aarch64"))
        ))]
        return self.renew_v3_profile_with_clock(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .and_then(|value| u64::try_from(value.as_millis()).ok())
                .ok_or(ProtectedBundledRuntimeError::LaunchAuthority(
                    LaunchAuthorityError::RenewalUnavailable,
                ))
        });
        #[cfg(not(unix))]
        return Err(ProtectedBundledRuntimeError::LaunchAuthority(
            LaunchAuthorityError::RenewalUnavailable,
        ));
    }
}

#[cfg(any(test, unix))]
include!("renewal_v3.rs");

#[cfg(all(test, unix))]
include!("renewal_v3_tests.rs");
