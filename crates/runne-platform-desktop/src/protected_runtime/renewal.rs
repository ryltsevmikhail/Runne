impl ProtectedBundledRuntimeProcess {
    /// Rotates the protected HTTP session without reusing launch authority.
    ///
    /// # Errors
    ///
    /// Returns a typed failure for stale ownership, replay, channel, or ticket proof failures.
    pub fn renew_profile(&mut self) -> Result<ProtectedBundledRuntimeProfile, ProtectedBundledRuntimeError> {
        #[cfg(not(any(unix, windows)))]
        { Err(ProtectedBundledRuntimeError::UnsupportedPlatformBackend) }
        #[cfg(any(unix, windows))]
        {
            if self.graceful_requested { return Err(ProtectedBundledRuntimeError::InvalidState); }
            let sequence = self.renewal_sequence.checked_add(1).ok_or(ProtectedBundledRuntimeError::InvalidState)?;
            let mut nonce = [0_u8; 32];
            OsRng.fill_bytes(&mut nonce);
            if nonce == [0; 32] { return Err(ProtectedBundledRuntimeError::LaunchAuthority(LaunchAuthorityError::RenewalUnavailable)); }
            let profile = match &mut self.activation {
                ProtectedProcessActivation::V1 { request, ready, owned } => {
                    let mut renewal = ProtectedRenewRequestV1::new(owned.clone(), sequence, nonce)?;
                    nonce.fill(0); renewal.sign(&self.keys);
                    write_frame(&mut self.channel, &Zeroizing::new(renewal.encode_frame().map_err(|_| LaunchAuthorityError::InvalidContract)?))?;
                    let ticket = ProtectedRenewTicketV1::decode_frame(&read_frame(&mut self.channel)?).map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
                    ticket.verify_exact(&renewal, &self.keys)?;
                    let profile = ProtectedBundledRuntimeProfile::from_renewal(ready, request, &renewal, &ticket, &self.keys)?;
                    *owned = ticket.next_owned_launch(); profile
                }
                ProtectedProcessActivation::V2 { request, ready, owned } => {
                    let mut renewal = ProtectedRenewRequestV2::new(owned.clone(), sequence, nonce)?;
                    nonce.fill(0); renewal.sign(&self.keys);
                    write_frame(&mut self.channel, &Zeroizing::new(renewal.encode_frame().map_err(|_| LaunchAuthorityError::InvalidContract)?))?;
                    let ticket = ProtectedRenewTicketV2::decode_frame(&read_frame(&mut self.channel)?).map_err(|_| LaunchAuthorityError::RenewalUnavailable)?;
                    ticket.verify_exact(&renewal, &self.keys)?;
                    let profile = ProtectedBundledRuntimeProfile::from_renewal_v2(ready, request, &renewal, &ticket, &self.keys)?;
                    *owned = ticket.next_owned_launch(); profile
                }
                #[cfg(feature = "test-support")]
                ProtectedProcessActivation::Test { .. } => return Err(ProtectedBundledRuntimeError::InvalidState),
            };
            self.renewal_sequence = sequence;
            Ok(profile)
        }
    }
}
