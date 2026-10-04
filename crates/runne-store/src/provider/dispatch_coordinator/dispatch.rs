impl<'a, P, E> SqliteProviderDispatchCoordinator<'a, P, E>
where
    P: ProviderPort + ?Sized,
    E: ProviderEffectPort + ?Sized,
{
    /// Executes ordered prepare, SQLite admission and one adapter dispatch.
    pub async fn dispatch(
        &self,
        request: ProviderCoordinatorRequest,
    ) -> Result<ProviderCoordinatorOutcome, ProviderAdmissionError> {
        self.dispatch_with_profile_grant(request, None).await
    }

    /// Dispatches one explicit secondary profile through its store-issued grant.
    pub async fn dispatch_secondary_profile(
        &self,
        request: ProviderCoordinatorRequest,
        grant: &super::ProviderSecondaryProfileGrant,
    ) -> Result<ProviderCoordinatorOutcome, ProviderAdmissionError> {
        self.dispatch_with_profile_grant(request, Some(grant)).await
    }

    async fn dispatch_with_profile_grant(
        &self,
        request: ProviderCoordinatorRequest,
        profile_grant: Option<&super::ProviderSecondaryProfileGrant>,
    ) -> Result<ProviderCoordinatorOutcome, ProviderAdmissionError> {
        let call_bytes =
            serde_json::to_vec(&request.call).map_err(|_| ProviderAdmissionError::PolicyDenied)?;
        match self
            .prohibited_content
            .inspect(CanonicalContentBoundary::OutboundDelivery, &call_bytes)
        {
            Ok(ContentDisposition::Allowed { .. }) => {}
            Ok(ContentDisposition::Prohibited { .. }) | Err(_) => {
                return Err(ProviderAdmissionError::PolicyDenied);
            }
        }
        let prepared = match self
            .dispatch_store
            .load_prepared(request.call.call_id())
            .map_err(|_| ProviderAdmissionError::RepositoryFailure)?
        {
            Some(record) => self
                .provider
                .prepare_for_digest_version(&request.call, record.call_digest_version),
            None => self.provider.prepare(&request.call),
        }
        .map_err(|_| ProviderAdmissionError::PrepareRejected)?;
        let prepared_record = PreparedProviderRecord {
            call_id: request.call.call_id(),
            call_digest_version: prepared.request_ref().digest_version(),
            prepared_digest: *prepared.request_ref().as_bytes(),
            render_digest: *prepared.render_digest(),
            profile_digest: request.profile_digest,
        };
        self.dispatch_store
            .persist_prepared(self.credential.launch, &prepared_record)
            .map_err(|error| match error {
                crate::provider::ProviderStoreError::StaleFencingToken => {
                    ProviderAdmissionError::StaleFencingToken
                }
                _ => ProviderAdmissionError::RepositoryFailure,
            })?;
        let issue = issue_request(
            &request,
            runne_provider::PreparedProviderRecord {
                call_id: prepared_record.call_id,
                call_digest_version: prepared_record.call_digest_version,
                prepared_digest: prepared_record.prepared_digest,
                render_digest: prepared_record.render_digest,
                profile_digest: prepared_record.profile_digest,
            },
        )?;
        let admission = match profile_grant {
            Some(grant) => {
                self.execution_store
                    .issue_secondary_profile(self.credential.launch, grant, &issue)
            }
            None => self.execution_store.issue(self.credential.launch, &issue),
        }?;
        let admitted = match admission {
            ProviderAuthorityIssueOutcome::Winner(admitted) => admitted,
            ProviderAuthorityIssueOutcome::Existing { state } => {
                return Ok(ProviderCoordinatorOutcome::Existing { state });
            }
        };
        let runtime_generation = admitted.runtime_generation();
        let claim = admitted.into_claim();
        let attempt_id = claim.attempt_id;
        let fencing_token = claim.fencing_token;
        if !claim_matches(&request, &issue, &claim) {
            let _ = self
                .dispatch_store
                .mark_uncertain(attempt_id, fencing_token);
            return Ok(ProviderCoordinatorOutcome::Uncertain);
        }
        let online = match self.credential.store.authorize_online_dispatch(
            self.credential.launch,
            &claim,
            self.execution_store.now(),
        ) {
            Ok(online) => online,
            Err(
                CredentialLifecycleError::InvalidInput
                | CredentialLifecycleError::NotFound
                | CredentialLifecycleError::Conflict
                | CredentialLifecycleError::LifecycleClosed
                | CredentialLifecycleError::StaleLease,
            ) => {
                return self.reject_before_effect(
                    attempt_id,
                    fencing_token,
                    ProviderPreEffectRejection::AdapterRejected,
                );
            }
            Err(
                CredentialLifecycleError::StoreUnavailable | CredentialLifecycleError::CorruptState,
            ) => {
                let _ = self
                    .dispatch_store
                    .mark_uncertain(attempt_id, fencing_token);
                return Ok(ProviderCoordinatorOutcome::Uncertain);
            }
        };
        let (credential, effect_binding) = online.split();
        if let Some(authority) = &self.subscription_budget
            && self.subscription_provider
            && !matches!(
                authority.seed_and_remaining(
                    request.call.model_ref().provider_id().as_str(),
                    credential.version_ref().version(),
                ),
                Ok(RemainingState::Remaining(_))
            )
        {
            return self.reject_before_effect(
                attempt_id,
                fencing_token,
                ProviderPreEffectRejection::BudgetDenied,
            );
        }
        let dispatch = match DispatchRequest::new(prepared, claim.clone()) {
            Ok(dispatch) => dispatch,
            Err(_) => {
                let _ = self
                    .dispatch_store
                    .mark_uncertain(attempt_id, fencing_token);
                return Ok(ProviderCoordinatorOutcome::Uncertain);
            }
        };

        let ready = match self.effect.stage_effect(dispatch, credential.clone()).await {
            Ok(ready) => ready,
            Err(DispatchError::RejectedBeforeEffect(reason)) => {
                return self.reject_before_effect(attempt_id, fencing_token, reason);
            }
            Err(_) => {
                let _ = self
                    .dispatch_store
                    .mark_uncertain(attempt_id, fencing_token);
                return Ok(ProviderCoordinatorOutcome::Uncertain);
            }
        };
        let effect = match self.execution_store.start_online_effect(
            self.credential.launch,
            &claim,
            &effect_binding,
        ) {
            Ok(effect) => effect.into_effect_receipt(),
            Err(
                ProviderAdmissionError::PostClaimUncertain
                | ProviderAdmissionError::StaleFencingToken,
            ) => {
                let _ = self
                    .dispatch_store
                    .mark_uncertain(attempt_id, fencing_token);
                return Ok(ProviderCoordinatorOutcome::Uncertain);
            }
            Err(_) => {
                return self.reject_before_effect(
                    attempt_id,
                    fencing_token,
                    ProviderPreEffectRejection::AdapterRejected,
                );
            }
        };
        let outcome = inflight::wait(self.effect.dispatch_effect(ready, effect), || {
            credential
                .validate_online_materialization(
                    self.credential,
                    &claim,
                    self.execution_store.now(),
                )
                .is_ok()
        })
        .await;
        match outcome {
            Ok(stream_id) => {
                if self
                    .dispatch_store
                    .mark_streaming_online(
                        &MarkProviderStreaming {
                            attempt_id,
                            fencing_token,
                            stream_id,
                        },
                        || self.execution_store.now(),
                    )
                    .is_err()
                {
                    let _ = self
                        .dispatch_store
                        .mark_uncertain(attempt_id, fencing_token);
                    inflight::cancel(self.provider, stream_id).await;
                    return Ok(ProviderCoordinatorOutcome::Uncertain);
                }
                Ok(ProviderCoordinatorOutcome::Streaming {
                    binding: Box::new(
                        ProviderExecutionBinding::new(
                            &claim,
                            runtime_generation,
                            prepared_record,
                            stream_id,
                        )
                        .bind_active_credential(credential),
                    ),
                })
            }
            Err(DispatchError::RejectedBeforeEffect(_)) => {
                let _ = self
                    .dispatch_store
                    .mark_uncertain(attempt_id, fencing_token);
                Ok(ProviderCoordinatorOutcome::Uncertain)
            }
            Err(
                DispatchError::MaybeDispatched
                | DispatchError::AttemptConflict
                | DispatchError::StreamNotFound,
            ) => {
                let _ = self
                    .dispatch_store
                    .mark_uncertain(attempt_id, fencing_token);
                Ok(ProviderCoordinatorOutcome::Uncertain)
            }
        }
    }
}
