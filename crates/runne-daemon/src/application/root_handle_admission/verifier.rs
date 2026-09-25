impl RootAdmissionVerifier for RootAdmissionGateway {
    fn verify_root_admission(
        &self,
        admission: RootHandleAdmission,
    ) -> Result<VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        let Some(authority) = &self.0 else {
            return Err(RootAdmissionVerifierError::Unavailable);
        };
        let claims = authority
            .authenticator
            .read()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?
            .verify(admission)
            .map_err(|_| RootAdmissionVerifierError::Rejected)?;
        // Verdicts are recomputed per command; they are never cached or memoized.
        let moment = now()?;
        let current = authority.context(moment)?;
        let mut state = authority
            .state
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        expire(&mut state, moment);
        let pending = state
            .pending
            .get(&claims.nonce())
            .ok_or(RootAdmissionVerifierError::Rejected)?;
        let matching = !state.stopped
            && claims.context().policy_version() == PINNED_POLICY_VERSION
            && same_context(claims.context(), &current)
            && claims.workspace_id() == pending.workspace
            && claims.expected_version() == pending.version
            && claims.filesystem_identity_digest() == pending.identity
            && claims.offer_digest() == pending.offer_digest
            && claims.admission_digest() == pending.digest
            && claims.expires_at_unix_millis() == pending.expires_at
            && pending.expires_at > moment;
        // Serving state is promoted only by confirm_root_admission after the
        // consuming command durably commits; verify stays a pure verdict.
        matching
            .then_some(claims)
            .ok_or(RootAdmissionVerifierError::Rejected)
    }

    fn confirm_root_admission(
        &self,
        claims: &VerifiedRootAdmissionClaims,
    ) -> Result<(), RootAdmissionVerifierError> {
        let Some(authority) = &self.0 else {
            return Err(RootAdmissionVerifierError::Unavailable);
        };
        let mut state = authority
            .state
            .lock()
            .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        promote_pending(&mut state, claims, now()?)
    }
}
