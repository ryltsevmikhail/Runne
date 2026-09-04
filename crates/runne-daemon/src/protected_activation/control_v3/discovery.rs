use super::*;

impl V3EnrollmentRuntime {
    pub(super) fn discover_cleanup(
        &self,
        channel: &mut ProtectedActivationChannel,
        keys: &ProtectedActivationKeys,
        owned: &ProtectedCredentialEnrollmentOwnedLaunchV3,
        sessions: &Mutex<LocalSessionService>,
        frame: &[u8],
    ) -> Result<(), LaunchAuthorityError> {
        if !self.terminal {
            return Err(LaunchAuthorityError::OwnershipMismatch);
        }
        let session = self
            .session
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let live = self
            .live
            .as_ref()
            .ok_or(LaunchAuthorityError::OwnershipMismatch)?;
        let mut codec = runne_api::ProtectedCredentialDiscoveryCodec::new(keys, owned);
        codec.decode_request(frame)?;
        let ids = live.with_current(sessions, || {
            session
                .require_durable_terminal()
                .map_err(runtime::map_enrollment_error)?;
            session
                .discover_cleanup()
                .map_err(runtime::map_enrollment_error)
        })?;
        // A new codec may answer a repeated read-only request. This creates no
        // attempt or claim; Desktop checks its fresh nonce before accepting it.
        channel.write_control_frame(&codec.encode_response(&ids)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protected_activation::enrollment_v3_tests::owned_and_sessions;

    #[test]
    fn discovery_without_enrollment_owner_returns_no_metadata_or_rotation() {
        use std::os::unix::net::UnixStream;
        let (owned, keys, sessions) = owned_and_sessions();
        let observed = Arc::clone(&sessions);
        let expected = sessions.lock().unwrap().current_binding().clone();
        let request = runne_api::ProtectedCredentialDiscoveryCodec::new(&keys, &owned)
            .encode_request([19; 32])
            .unwrap();
        let (mut peer, stream) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let server = std::thread::spawn(move || {
            run_control_loop_v3(ProtectedActivationChannel::new(stream).unwrap(), keys, owned,
                sessions, Arc::new(|| Duration::from_secs(1)), Arc::new(|| Ok(1_000)),
                crate::protected_activation::enrollment_control_transition::DaemonEnrollmentRendezvous::for_test())
        });
        peer.write_all(&request).unwrap();
        assert_eq!(
            server.join().unwrap(),
            Err(LaunchAuthorityError::OwnershipMismatch)
        );
        assert_eq!(peer.read(&mut [0; 1]).unwrap(), 0);
        assert_eq!(observed.lock().unwrap().current_binding(), &expected);
    }
}
