use super::{
    BundledRuntimeLifecycleState, EnrollmentBrokerFacts, ProtectedBundledRuntimeError,
    ProtectedBundledRuntimeSupervisor, ProtectedProcessActivation, random_nonce, read_frame,
    write_frame,
};

fn terminal_is_from_prior_session(terminal: Option<[u8; 16]>, current: [u8; 16]) -> bool {
    terminal.is_some_and(|terminal| terminal != current)
}

fn linux_v3_enrollment_facts(
    process: &super::ProtectedBundledRuntimeProcess,
) -> Result<
    (
        runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
        EnrollmentBrokerFacts,
    ),
    ProtectedBundledRuntimeError,
> {
    let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
        return Err(ProtectedBundledRuntimeError::InvalidState);
    };
    Ok((
        owned.clone(),
        process
            .enrollment_broker_facts
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?,
    ))
}

impl ProtectedBundledRuntimeSupervisor {
    /// Reports whether an operation completed and a successor session is required.
    ///
    /// # Errors
    /// Returns an error unless the active supervisor owns an entered V3 session.
    pub fn linux_credential_enrollment_has_terminal_operation(
        &self,
    ) -> Result<bool, ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_ref()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let (_, facts) = linux_v3_enrollment_facts(process)?;
        Ok(facts.terminal_session.is_some())
    }

    /// Exchanges fresh Linux broker facts after a terminal operation and renewal.
    ///
    /// # Errors
    /// Rejects missing terminal evidence or an unchanged session and fences ambiguous I/O.
    pub fn begin_next_linux_protected_credential_round(
        &mut self,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        let (owned, facts) = linux_v3_enrollment_facts(process)?;
        if process.graceful_requested
            || !terminal_is_from_prior_session(facts.terminal_session, *owned.session_id())
        {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }

        let mut codec = runne_api::ProtectedCredentialRoundCodec::new(&process.keys, &owned);
        let nonce = random_nonce().ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        let request = codec
            .encode_request(nonce)
            .map_err(|_| ProtectedBundledRuntimeError::InvalidState)?;
        process.enrollment_broker_facts = None;
        let result = (|| {
            write_frame(&mut process.channel, &request)?;
            let offered = codec
                .decode_offer(&read_frame(&mut process.channel)?)
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            let accept = codec
                .encode_accept()
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
            write_frame(&mut process.channel, &accept)?;
            Ok::<_, ProtectedBundledRuntimeError>(EnrollmentBrokerFacts::new(
                offered.channel_binding(),
                offered.publication_key(),
            ))
        })();
        match result {
            Ok(facts) => {
                process.enrollment_broker_facts = Some(facts);
                Ok(())
            }
            Err(error) => {
                process.fence_ambiguous_transition();
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{os::unix::net::UnixStream, time::Duration};

    fn round_supervisor(
        channel: UnixStream,
    ) -> (
        ProtectedBundledRuntimeSupervisor,
        runne_api::ProtectedActivationKeys,
        runne_api::ProtectedCredentialEnrollmentOwnedLaunchV3,
    ) {
        let (mut process, keys) = super::super::v3_process(channel);
        let ProtectedProcessActivation::V3 { owned, .. } = &process.activation else {
            panic!("V3 fixture");
        };
        let owned = owned.clone();
        let mut facts = EnrollmentBrokerFacts::new([31; 32], [32; 32]);
        facts.terminal_session = Some([77; 16]);
        process.enrollment_broker_facts = Some(facts);
        let root = std::env::temp_dir().join(format!("runne-linux-round-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let spec = super::super::ProtectedBundledRuntimeLaunchSpec::new(
            std::path::Path::new("/bin/sleep"),
            &root,
        )
        .unwrap();
        let supervisor = ProtectedBundledRuntimeSupervisor {
            launcher: super::super::DevelopmentBundledRuntimeLauncher::new(),
            spec,
            process: Some(process),
            pending_profile: None,
            backoff: super::super::BundledRuntimeBackoff::new(),
            restart_at: None,
            state: BundledRuntimeLifecycleState::Ready,
        };
        let _ = std::fs::remove_dir(root);
        (supervisor, keys, owned)
    }

    #[test]
    fn round_requires_terminal_and_a_successor_session_before_io() {
        let (channel, _peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let (mut supervisor, _, owned) = round_supervisor(channel);
        let process = supervisor.process.as_mut().unwrap();
        process
            .enrollment_broker_facts
            .as_mut()
            .unwrap()
            .terminal_session = None;
        assert!(
            supervisor
                .begin_next_linux_protected_credential_round()
                .is_err()
        );
        supervisor
            .process
            .as_mut()
            .unwrap()
            .enrollment_broker_facts
            .as_mut()
            .unwrap()
            .terminal_session = Some(*owned.session_id());
        assert!(
            supervisor
                .begin_next_linux_protected_credential_round()
                .is_err()
        );
        assert!(
            supervisor
                .process
                .as_ref()
                .unwrap()
                .enrollment_broker_facts
                .is_some()
        );
        supervisor.stop().unwrap();
    }

    #[test]
    fn authenticated_offer_replaces_terminal_broker_facts() {
        let (channel, mut peer) = UnixStream::pair().unwrap();
        channel
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let (mut supervisor, keys, owned) = round_supervisor(channel);
        let daemon = std::thread::spawn(move || {
            let mut codec = runne_api::ProtectedCredentialRoundCodec::new(&keys, &owned);
            codec
                .decode_request(&read_frame(&mut peer).unwrap())
                .unwrap();
            let offer = codec
                .encode_offer(
                    runne_api::ProtectedCredentialRoundBrokerFacts::new([41; 32], [42; 32])
                        .unwrap(),
                )
                .unwrap();
            write_frame(&mut peer, &offer).unwrap();
            codec
                .decode_accept(&read_frame(&mut peer).unwrap())
                .unwrap();
        });
        supervisor
            .begin_next_linux_protected_credential_round()
            .unwrap();
        let facts = supervisor
            .process
            .as_ref()
            .unwrap()
            .enrollment_broker_facts
            .unwrap();
        assert_eq!(facts.binding(), [41; 32]);
        assert_eq!(facts.publication_public_key(), [42; 32]);
        daemon.join().unwrap();
        supervisor.stop().unwrap();
    }
}
