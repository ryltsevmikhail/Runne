use super::*;

impl ProviderEffectPort for OnlineDispatchFence<'_> {
    fn stage_effect(
        &self,
        request: DispatchRequest,
        credential: CredentialDispatchBinding,
    ) -> ProviderFuture<'_, Result<Box<dyn ProviderReadyEffect>, DispatchError>> {
        Box::pin(async move {
            if credential
                .validate_online_materialization(
                    self.authority,
                    request.claim(),
                    chrono::Utc::now().timestamp(),
                )
                .is_err()
            {
                return Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ));
            }
            let intent = ProviderRequestIntent {
                claim: request.claim().clone(),
                prepared: request.prepared().clone(),
            };
            let prepared = request.prepared();
            let prepared_request = PreparedTaskRunProviderRequest {
                call_id: prepared.call().call_id(),
                call_digest_version: prepared.request_ref().digest_version(),
                prepared_digest: *prepared.request_ref().as_bytes(),
                render_digest: *prepared.render_digest(),
                profile_digest: request.claim().profile_digest,
                provider_idempotency_key: request.provider_idempotency_key().into(),
            };
            let taskrun_binding =
                if let Some((identity, original_claim_version, round, profile_digest)) =
                    &self.taskrun_round
                {
                    let binding =
                        TaskRunPreparedBinding::ToolRound(BindPreparedTaskRunProviderRoundEffect {
                            identity: identity.clone(),
                            original_claim_version: *original_claim_version,
                            current_taskrun_head: round.current_taskrun_head,
                            round_index: round.round_index,
                            previous_tool_result: round.previous_tool_result,
                            prepared: PreparedTaskRunProviderRequest {
                                profile_digest: *profile_digest,
                                ..prepared_request
                            },
                        });
                    bind_taskrun_request(self.taskrun_store, &binding, false).map_err(
                        |_error| {
                            DispatchError::RejectedBeforeEffect(
                                ProviderPreEffectRejection::AdapterRejected,
                            )
                        },
                    )?;
                    Some(binding)
                } else if let Some((identity, expected_claim_version, profile_digest)) =
                    &self.taskrun
                {
                    let binding = TaskRunPreparedBinding::Legacy(
                        runne_application::ports::BindPreparedTaskRunProviderEffect {
                            identity: identity.clone(),
                            expected_claim_version: *expected_claim_version,
                            prepared: PreparedTaskRunProviderRequest {
                                profile_digest: *profile_digest,
                                ..prepared_request
                            },
                        },
                    );
                    bind_taskrun_request(self.taskrun_store, &binding, false).map_err(
                        |_error| {
                            DispatchError::RejectedBeforeEffect(
                                ProviderPreEffectRejection::AdapterRejected,
                            )
                        },
                    )?;
                    Some(binding)
                } else {
                    None
                };
            let ready = self.inner.stage_effect(request, credential).await?;
            wait_for_t1_test_barrier("stage-ready").await?;
            let lease = match &self.trust {
                Some(context) => context
                    .gate
                    .acquire_provider_effect_lease(&context.principal, context.conversation_id)
                    .map_err(|_| {
                        DispatchError::RejectedBeforeEffect(
                            ProviderPreEffectRejection::AdapterRejected,
                        )
                    })?,
                None => None,
            };
            if lease.is_some() {
                wait_for_t1_test_barrier("lease-held").await?;
            }
            Ok(Box::new(LeasedReadyEffect {
                ready,
                lease,
                taskrun_binding,
                intent,
                #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
                continuation_target_fence: self
                    .taskrun_round
                    .as_ref()
                    .and_then(|(_, _, round, _)| round.continuation_target_fence.clone()),
            }) as Box<dyn ProviderReadyEffect>)
        })
    }

    fn dispatch_effect(
        &self,
        ready: Box<dyn ProviderReadyEffect>,
        receipt: ProviderEffectStartReceipt,
    ) -> ProviderFuture<'_, Result<ProviderStreamId, DispatchError>> {
        let ready = ready.into_any();
        let Ok(ready) = ready.downcast::<LeasedReadyEffect>() else {
            return Box::pin(async { Err(DispatchError::MaybeDispatched) });
        };
        let LeasedReadyEffect {
            ready,
            lease,
            taskrun_binding,
            intent,
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            continuation_target_fence,
        } = *ready;
        if let Some(binding) = &taskrun_binding
            && bind_taskrun_request(self.taskrun_store, binding, true).is_err()
        {
            return Box::pin(async {
                Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ))
            });
        }
        if !receipt.matches_claim(&intent.claim) {
            return Box::pin(async { Err(DispatchError::MaybeDispatched) });
        }
        let request_intents = Arc::clone(&self.request_intents);
        let provider_id = self.provider_id.clone();
        let credential_realm = self.credential_realm.clone();
        let profile_id = self.profile_id.clone();
        let taskrun_store = self.taskrun_store;
        let inner = self.inner;
        Box::pin(async move {
            let context = request_intents
                .for_new_dispatch(&intent.claim, &provider_id, &credential_realm, &profile_id)
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            context
                .persist_request(intent.prepared.rendered_bytes())
                .await
                .map_err(|_| DispatchError::MaybeDispatched)?;
            #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
            if continuation_target_fence
                .as_ref()
                .is_some_and(|fence| fence.validate().is_err())
            {
                return Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ));
            }
            // Intent persistence can yield while a caller accepts cancellation.
            // Recheck at the last wrapper-controlled point before the adapter
            // begins materialization or transport. A stale receipt remains an
            // audit fact, but cannot authorize a fresh adapter dispatch.
            if let Some(binding) = &taskrun_binding
                && bind_taskrun_request(taskrun_store, binding, true).is_err()
            {
                return Err(DispatchError::RejectedBeforeEffect(
                    ProviderPreEffectRejection::AdapterRejected,
                ));
            }
            // Keep project trust held through adapter materialization and
            // transport. The final TaskRun recheck above is the gate's
            // linearization point; a cancellation committed after it is an
            // already-started uncertain outcome, never a second dispatch.
            let outcome = inner.dispatch_effect(ready, receipt).await;
            drop(lease);
            outcome
        })
    }
}
