use runne_local_store::ClientMutationDisposition as State;

impl AppCore {
    async fn dispatch_prepared_mutation_under_operation(
        &self,
        lease: &mut PreparedMutationLease,
        possible_send: Option<&mut bool>,
        defer_workspace_open_outcome: bool,
        _composite_failure: bool,
        recovery: bool,
    ) -> Result<MutationDispatchResult, AppCoreError> {
        let anchored = lease
            .anchored_record
            .normalized_command()
            .ok_or(AppCoreError::MutationUnavailable)?;
        request_matches_anchored_command(&lease.request, anchored)?;
        #[cfg(any(test, feature = "test-support"))]
        if self
            .mutation_test_hold_before_dispatch
            .load(Ordering::Acquire)
        {
            self.mutation_test_before_dispatch.notify_one();
            std::future::pending::<()>().await;
        }
        let state = lease.anchored_record.disposition();
        self.prepare_and_dispatch(lease, state, possible_send, recovery)
            .await?;
        self.fence_stale_network_result(lease, recovery)?;
        let observed = self.reconcile_anchored_command(lease, recovery).await;
        self.fence_stale_network_result(lease, recovery)?;
        let disposition = lease.anchored_record.disposition();
        self.finish_dispatch(lease, observed, disposition, defer_workspace_open_outcome)
            .await
    }

    fn fence_stale_network_result(
        &self,
        lease: &mut PreparedMutationLease,
        recovery: bool,
    ) -> Result<(), AppCoreError> {
        let current = if recovery {
            self.recovery_dispatch_client(lease)
        } else {
            self.final_dispatch_client(lease)
        };
        if current.is_ok() {
            return Ok(());
        }
        if matches!(
            lease.anchored_record.disposition(),
            State::Dispatching | State::Observing
        ) {
            self.transition_v7_under_operation(
                lease,
                runne_local_store::V7MutationTransition::Indeterminate {
                    timestamp: unix_timestamp(),
                },
            )?;
        }
        Err(AppCoreError::RuntimeUnavailable)
    }

    async fn prepare_and_dispatch(
        &self,
        lease: &mut PreparedMutationLease,
        state: runne_local_store::ClientMutationDisposition,
        mut possible_send: Option<&mut bool>,
        recovery: bool,
    ) -> Result<(), AppCoreError> {
        use runne_local_store::ClientMutationDisposition as State;
        if state == State::ManualResolution {
            return Err(AppCoreError::MutationUnavailable);
        }
        if recovery && state == State::Prepared {
            self.close_manual_resolution(lease)?;
            return Err(AppCoreError::MutationUnavailable);
        }
        match state {
            State::Prepared => {
                self.transition_v7_under_operation(
                    lease,
                    runne_local_store::V7MutationTransition::Dispatching {
                        timestamp: unix_timestamp(),
                    },
                )?;
                if Self::can_resend_bind(lease) {
                    Self::mark_possible_send(&mut possible_send);
                    self.send_or_classify_prohibited_input(lease, recovery)
                        .await?;
                }
            }
            State::Retryable => {
                self.retry_mutation(lease, &mut possible_send, recovery)
                    .await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn retry_mutation(
        &self,
        lease: &mut PreparedMutationLease,
        possible_send: &mut Option<&mut bool>,
        recovery: bool,
    ) -> Result<(), AppCoreError> {
        let unsafe_recovery_bind = recovery
            && matches!(
                lease.request.semantic_command,
                CanonicalMutationCommand::BindWorkspaceRoot { .. }
            );
        if lease.anchored_record.resend_count() != 0
            || !Self::can_resend_bind(lease)
            || unsafe_recovery_bind
        {
            self.close_manual_resolution(lease)?;
            return Err(AppCoreError::MutationUnavailable);
        }
        self.resend_v7_under_operation(lease, unix_timestamp())?;
        Self::mark_possible_send(possible_send);
        self.send_or_classify_prohibited_input(lease, recovery)
            .await?;
        Ok(())
    }

    async fn send_or_classify_prohibited_input(
        &self,
        lease: &mut PreparedMutationLease,
        recovery: bool,
    ) -> Result<(), AppCoreError> {
        match self.send_exact_command(lease, recovery).await {
            Err(AppCoreError::ProhibitedInputRejected)
                if lease.anchored_record.disposition()
                    == runne_local_store::ClientMutationDisposition::Dispatching
                    && lease.anchored_record.resend_count() == 0
                    && matches!(
                        &lease.request.semantic_command,
                        CanonicalMutationCommand::GenerateText { .. }
                    ) =>
            {
                self.transition_v7_under_operation(
                    lease,
                    runne_local_store::V7MutationTransition::ProhibitedInputRejectedBeforeAdmission {
                        timestamp: unix_timestamp(),
                    },
                )?;
                Err(AppCoreError::ProhibitedInputRejected)
            }
            // A resend (resend_count > 0) is past the one valid refusal
            // transition; the pre-effect provider rejection is still an
            // error and is never swallowed into a successful dispatch.
            Err(AppCoreError::ProhibitedInputRejected) => {
                Err(AppCoreError::ProhibitedInputRejected)
            }
            Err(AppCoreError::GenerationOutcomeUnknown) => {
                if matches!(
                    lease.anchored_record.disposition(),
                    runne_local_store::ClientMutationDisposition::Dispatching
                        | runne_local_store::ClientMutationDisposition::Observing
                ) {
                    self.transition_v7_under_operation(
                        lease,
                        runne_local_store::V7MutationTransition::Indeterminate {
                            timestamp: unix_timestamp(),
                        },
                    )?;
                }
                Err(AppCoreError::GenerationOutcomeUnknown)
            }
            // A previous send may have committed, so keep the normal reconciliation path.
            _ => Ok(()),
        }
    }

    async fn finish_dispatch(
        &self,
        lease: &mut PreparedMutationLease,
        observed: Result<
            runne_runtime_client::CommandReconciliationDisposition,
            ReconciliationFailure,
        >,
        original_disposition: runne_local_store::ClientMutationDisposition,
        defer_workspace_open_outcome: bool,
    ) -> Result<MutationDispatchResult, AppCoreError> {
        use runne_local_store::ClientMutationDisposition as State;
        if original_disposition == State::CanonicalOutcome {
            return match observed {
                Ok(runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
                    outcome,
                )) => {
                    self.persist_reconciled_outcome(lease, &outcome).await?;
                    Self::project_reconciled_result(&outcome)
                }
                Ok(_) | Err(_) => Err(AppCoreError::MutationUnavailable),
            };
        }
        match observed {
            Ok(runne_runtime_client::CommandReconciliationDisposition::DurablyRecorded(
                outcome,
            )) => {
                self.persist_reconciled_outcome(lease, &outcome).await?;
                if defer_workspace_open_outcome {
                    return Self::project_reconciled_result(&outcome);
                }
                Self::project_reconciled_result(&outcome)
            }
            Ok(runne_runtime_client::CommandReconciliationDisposition::NotCommittedRetryable) => {
                if original_disposition == State::Observing {
                    self.transition_v7_under_operation(
                        lease,
                        runne_local_store::V7MutationTransition::Indeterminate {
                            timestamp: unix_timestamp(),
                        },
                    )?;
                }
                self.transition_v7_under_operation(
                    lease,
                    runne_local_store::V7MutationTransition::NotCommittedRetryable {
                        timestamp: unix_timestamp(),
                    },
                )?;
                Err(AppCoreError::RuntimeUnavailable)
            }
            Err(
                ReconciliationFailure::Runtime(
                    runne_runtime_client::RuntimeApiErrorKind::Conflict
                    | runne_runtime_client::RuntimeApiErrorKind::InvalidResponse,
                )
                | ReconciliationFailure::Local,
            ) => {
                self.close_manual_resolution(lease)?;
                Err(AppCoreError::MutationUnavailable)
            }
            Ok(runne_runtime_client::CommandReconciliationDisposition::Indeterminate)
            | Err(ReconciliationFailure::Unavailable | ReconciliationFailure::Runtime(_)) => {
                if original_disposition != State::Reconciling {
                    self.transition_v7_under_operation(
                        lease,
                        runne_local_store::V7MutationTransition::Indeterminate {
                            timestamp: unix_timestamp(),
                        },
                    )?;
                }
                Err(AppCoreError::RuntimeUnavailable)
            }
        }
    }

    fn mark_possible_send(possible_send: &mut Option<&mut bool>) {
        if let Some(value) = possible_send.as_deref_mut() {
            *value = true;
        }
    }
}
