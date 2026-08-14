impl LocalSessionService {
    /// Issues one challenge using caller-supplied deterministic entropy and monotonic time.
    pub fn issue_challenge(
        &mut self,
        client_nonce: [u8; 32],
        server_nonce: [u8; 32],
        now: Duration,
    ) -> Result<LocalSessionChallenge, LocalSessionError> {
        self.prune(now);
        self.enforce_bootstrap_deadline(now)?;
        if self.bootstrap_secret.is_none() {
            return Err(LocalSessionError::Unauthorized);
        }
        if self.challenges.len() >= MAX_CHALLENGES || self.issued.len() >= MAX_ISSUED_PER_MINUTE {
            return Err(LocalSessionError::Unavailable);
        }
        let id =
            LocalSessionChallengeId(server_nonce[..16].try_into().expect("fixed nonce prefix"));
        if self.challenges.contains_key(&id) {
            return Err(LocalSessionError::Unavailable);
        }
        self.challenges.insert(
            id,
            Challenge {
                client_nonce,
                server_nonce,
                issued_at: now,
            },
        );
        self.issued.push_back(now);
        Ok(LocalSessionChallenge { id, server_nonce })
    }

    /// Verifies and consumes a challenge before issuing a ten-minute authority.
    pub fn authenticate(
        &mut self,
        id: LocalSessionChallengeId,
        proof: BootstrapProof,
        authority_bytes: [u8; 32],
        now: Duration,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.prune(now);
        self.enforce_bootstrap_deadline(now)?;
        let Some(challenge) = self.challenges.remove(&id) else {
            return Err(LocalSessionError::Unauthorized);
        };
        if now.saturating_sub(challenge.issued_at) > CHALLENGE_TTL || authority_bytes == [0; 32] {
            return Err(LocalSessionError::Unauthorized);
        }
        let transcript = bootstrap_proof_transcript(
            &self.binding,
            challenge.server_nonce,
            challenge.client_nonce,
        );
        let Some(bootstrap_secret) = self.bootstrap_secret.as_ref() else {
            return Err(LocalSessionError::Unauthorized);
        };
        let mut mac = HmacSha256::new_from_slice(bootstrap_secret.as_ref())
            .expect("HMAC accepts any key length");
        mac.update(&transcript);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        if !bool::from(expected.ct_eq(&proof.0)) {
            return Err(LocalSessionError::Unauthorized);
        }
        let principal = self.binding.stable().principal_id().as_str();
        if self.sessions.len() >= MAX_SESSIONS
            || self
                .sessions
                .values()
                .filter(|session| {
                    session
                        .authenticated
                        .binding
                        .stable()
                        .principal_id()
                        .as_str()
                        == principal
                })
                .count()
                >= MAX_SESSIONS_PER_PRINCIPAL
        {
            return Err(LocalSessionError::Unavailable);
        }
        let authenticated = AuthenticatedRuntimeSession {
            binding: self.binding.clone(),
            expires_at_monotonic: now + LOCAL_RUNTIME_SESSION_TTL,
        };
        self.sessions.insert(
            authority_bytes,
            Session {
                authenticated: authenticated.clone(),
                authority: RuntimeSessionAuthority(Zeroizing::new(authority_bytes)),
                epoch: self.authorization_epoch,
                generation: self.binding.ephemeral().launch_generation(),
                issuer_state: Arc::new(ReplayBaselineIssuerState {
                    revoked: AtomicBool::new(false),
                }),
            },
        );
        if self.bootstrap_policy == BootstrapPolicy::OneTimeProtected {
            self.bootstrap_secret.take();
            self.bootstrap_expires_at = None;
            self.challenges.clear();
        }
        Ok(authenticated)
    }

    /// Installs the next one-time bootstrap for the exact same owned launch.
    ///
    /// Rotation changes only the HTTP session identity. Stable authority,
    /// daemon instance, launch generation, authorization epoch, sensitivity,
    /// and certificate identity must remain exact.
    pub fn rotate_protected_bootstrap(
        &mut self,
        binding: RuntimeSessionBinding,
        bootstrap_secret: [u8; 32],
        now: Duration,
        expires_at: Duration,
    ) -> Result<(), LocalSessionError> {
        let current_ephemeral = self.binding.ephemeral();
        let next_ephemeral = binding.ephemeral();
        if self.bootstrap_policy != BootstrapPolicy::OneTimeProtected
            || bootstrap_secret == [0; 32]
            || self.binding.stable() != binding.stable()
            || current_ephemeral.daemon_instance_id() != next_ephemeral.daemon_instance_id()
            || current_ephemeral.launch_generation() != next_ephemeral.launch_generation()
            || current_ephemeral.session_id() == next_ephemeral.session_id()
            || current_ephemeral.authorization_epoch() != next_ephemeral.authorization_epoch()
            || current_ephemeral.sensitivity_ceiling() != next_ephemeral.sensitivity_ceiling()
            || self.binding.certificate_sha256() != binding.certificate_sha256()
            || expires_at <= now
            || expires_at.saturating_sub(now) > MAX_PROTECTED_BOOTSTRAP_TTL
        {
            return Err(LocalSessionError::Unauthorized);
        }
        self.binding = binding;
        self.bootstrap_secret = Some(Zeroizing::new(bootstrap_secret));
        self.bootstrap_expires_at = Some(expires_at);
        self.challenges.clear();
        for session in self.sessions.values() {
            session.issuer_state.revoked.store(true, Ordering::Release);
        }
        self.sessions.clear();
        Ok(())
    }

    fn enforce_bootstrap_deadline(&mut self, now: Duration) -> Result<(), LocalSessionError> {
        if self
            .bootstrap_expires_at
            .is_some_and(|expires_at| now > expires_at)
        {
            self.bootstrap_secret.take();
            self.bootstrap_expires_at = None;
            self.challenges.clear();
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(())
    }

    /// Revokes all authorities from an earlier authorization epoch.
    pub fn set_authorization_epoch(&mut self, epoch: u64) {
        self.authorization_epoch = epoch;
        self.sessions.retain(|_, session| {
            let keep = session.epoch == epoch;
            if !keep {
                session.issuer_state.revoked.store(true, Ordering::Release);
            }
            keep
        });
    }

    /// Updates the replay ceiling and revokes issuers bound to the prior ceiling.
    pub fn set_sensitivity_ceiling(&mut self, ceiling: Sensitivity) {
        if self.sensitivity_ceiling != ceiling {
            self.sessions
                .values()
                .for_each(|session| session.issuer_state.revoked.store(true, Ordering::Release));
        }
        self.sensitivity_ceiling = ceiling;
    }

    /// Returns the current replay authorization for the bound principal and
    /// daemon generation.
    pub fn current_replay_authorization(
        &self,
        principal_id: &str,
        generation: u64,
    ) -> Result<LocalReplayAuthorizationState, LocalSessionError> {
        if principal_id != self.binding.stable().principal_id().as_str()
            || generation != self.binding.ephemeral().launch_generation()
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(LocalReplayAuthorizationState {
            authorization_epoch: self.authorization_epoch,
            sensitivity_ceiling: self.sensitivity_ceiling,
        })
    }

    /// Validates a session against the service's current binding.
    pub fn authorize_wire(
        &mut self,
        authority: &[u8; 32],
        now: Duration,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.authorize_wire_for_binding(authority, &self.binding.clone(), now)
    }

    /// Validates a session against an explicit launch binding, for composition roots that rotate generations.
    pub fn authorize_wire_for_binding(
        &mut self,
        authority: &[u8; 32],
        binding: &RuntimeSessionBinding,
        now: Duration,
    ) -> Result<AuthenticatedRuntimeSession, LocalSessionError> {
        self.prune(now);
        let Some(session) = self.sessions.get(authority) else {
            return Err(LocalSessionError::Unauthorized);
        };
        if !session.authority.verifies(authority)
            || session.epoch != self.authorization_epoch
            || session.generation != binding.ephemeral().launch_generation()
            || session.authenticated.binding != *binding
        {
            return Err(LocalSessionError::Unauthorized);
        }
        Ok(session.authenticated.clone())
    }
    fn prune(&mut self, now: Duration) {
        self.challenges
            .retain(|_, challenge| now.saturating_sub(challenge.issued_at) <= CHALLENGE_TTL);
        while self
            .issued
            .front()
            .is_some_and(|issued| now.saturating_sub(*issued) >= Duration::from_secs(60))
        {
            self.issued.pop_front();
        }
        self.sessions.retain(|_, session| {
            let keep = now < session.authenticated.expires_at_monotonic;
            if !keep {
                session.issuer_state.revoked.store(true, Ordering::Release);
            }
            keep
        });
    }
}
