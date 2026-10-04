struct Contexts {
    profile_digest: [u8; 32],
    semantic_digest: [u8; 32],
    profile_id: String,
    pricing_digest: [u8; 32],
    sink: Arc<IdentitySink>,
    wrong_attempt: bool,
    taskrun_id: TaskRunId,
    task_attempt_id: AttemptId,
    authority_id: [u8; 16],
    database_generation: u64,
    runtime_generation: u64,
}

impl Contexts {
    fn context(
        &self,
        claim: &runne_provider::ProviderDispatchClaim,
    ) -> Result<ProviderRecoveryDispatchContext, ProviderRecoveryError> {
        let attempt = if self.wrong_attempt {
            DispatchAttemptId::from_bytes([0x33; 16])
        } else {
            claim.attempt_id
        };
        let binding = ProviderRecoveryBinding::new(
            self.taskrun_id,
            self.task_attempt_id,
            attempt,
            self.profile_digest,
        )?;
        let identity = ProviderRecoveryAttemptIdentity::new(
            claim.provider_id.clone(),
            ProviderId::new("openai-background").unwrap(),
            self.profile_id.clone(),
            claim.profile_digest,
            self.semantic_digest,
            claim.prepared_digest,
            self.pricing_digest,
            claim.render_digest,
            self.authority_id,
            self.database_generation,
            self.runtime_generation,
            claim.fencing_token,
        )?;
        let context =
            ProviderRecoveryDispatchContext::new_exact(binding, identity, self.sink.clone());
        assert_eq!(
            context.matches_claim(claim.attempt_id, claim.profile_digest),
            !self.wrong_attempt
        );
        let identity = context.identity().expect("exact fixture identity");
        assert_eq!(identity.provider_id().as_str(), "openai-background");
        assert_eq!(identity.credential_realm().as_str(), "openai-background");
        assert_eq!(identity.profile_id(), self.profile_id);
        assert_eq!(identity.profile_digest(), &claim.profile_digest);
        assert_eq!(identity.semantic_digest(), &self.semantic_digest);
        assert_eq!(identity.prepared_digest(), &claim.prepared_digest);
        assert_eq!(identity.request_digest(), &claim.render_digest);
        assert_eq!(identity.pricing_digest(), &self.pricing_digest);
        Ok(context)
    }
}

impl ProviderRecoveryDispatchContextProvider for Contexts {
    fn for_dispatch<'a>(
        &'a self,
        claim: &'a runne_provider::ProviderDispatchClaim,
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        let result = self.context(claim);
        Box::pin(async move { result })
    }

    fn for_persisted_new_dispatch<'a>(
        &'a self,
        claim: &'a runne_provider::ProviderDispatchClaim,
        _: &'a ProviderId,
        _: &'a ProviderId,
        _: &'a str,
        rendered_request: &'a [u8],
    ) -> ProviderFuture<'a, Result<ProviderRecoveryDispatchContext, ProviderRecoveryError>> {
        let result = self.context(claim);
        Box::pin(async move {
            let context = result?;
            context.persist_request(rendered_request).await?;
            Ok(context)
        })
    }
}
