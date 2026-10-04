use super::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::ports::{
    CompleteClaimedTaskRunCancellationInput, CompleteQueuedCancellationInput,
    TaskRunCancellationScanner, TaskRunQueueCandidate, TaskRunQueueScanner,
};
use runne_runtime::taskrun_auto_worker::{
    AutomaticTaskRunError, AutomaticTaskRunService, SavedRemoteObservationProgress,
};

impl AutomaticTaskRunService for DaemonAutomaticTaskRuns {
    fn scan_queued(
        &self,
        after: Option<runne_domain::id::TaskRunId>,
        limit: usize,
    ) -> Result<
        runne_application::ports::TaskRunQueueScanPage,
        runne_application::ports::EventStoreError,
    > {
        let request = runne_application::ports::TaskRunQueueScanRequest::new(after, limit)
            .ok_or(runne_application::ports::EventStoreError::Unavailable)?;
        self.store.scan_queued_task_runs(request)
    }

    fn scan_pending_cancellations(
        &self,
        after: Option<runne_domain::id::TaskRunId>,
        limit: usize,
    ) -> Result<
        runne_application::ports::TaskRunQueueScanPage,
        runne_application::ports::EventStoreError,
    > {
        let request = runne_application::ports::TaskRunQueueScanRequest::new(after, limit)
            .ok_or(runne_application::ports::EventStoreError::Unavailable)?;
        self.store.scan_pending_taskrun_cancellations(request)
    }

    fn execute_queued(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> runne_provider::ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(self.execute_one(candidate))
    }

    fn observe_saved_remote_page(
        &self,
        after: Option<runne_provider::DispatchAttemptId>,
        limit: usize,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<SavedRemoteObservationProgress, AutomaticTaskRunError>,
    > {
        Box::pin(async move {
            let Some(provider) = self.provider.as_ref() else {
                return Ok(SavedRemoteObservationProgress {
                    next_after: None,
                    reached_end: true,
                    unavailable_candidates: 0,
                });
            };
            // One 1s scan plus four 4s candidate budgets stay below the
            // worker's 20s page deadline.
            if !(1..=4).contains(&limit) {
                return Err(AutomaticTaskRunError::Unavailable);
            }
            let page = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                provider.scan_saved_remote_candidate_ids_bounded(after, limit),
            )
            .await
            .map_err(|_| AutomaticTaskRunError::Unavailable)?
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
            if !page.attempts.is_empty() && page.next_after.is_none() {
                return Err(AutomaticTaskRunError::Unavailable);
            }
            let mut unavailable = 0_usize;
            for id in page.attempts {
                let classified = tokio::time::timeout(
                    std::time::Duration::from_millis(500),
                    provider.classify_saved_remote_candidate_by_id_bounded(id),
                )
                .await;
                let candidate = match classified {
                    Ok(Ok(candidate)) => candidate,
                    Ok(Err(_)) | Err(_) => {
                        unavailable = unavailable.saturating_add(1);
                        continue;
                    }
                };
                if let Some(candidate) = candidate {
                    let observed = tokio::time::timeout(
                        std::time::Duration::from_millis(3500),
                        provider.observe_saved_remote_candidate(candidate),
                    )
                    .await;
                    if !matches!(observed, Ok(Ok(_))) {
                        unavailable = unavailable.saturating_add(1);
                    }
                }
            }
            Ok(SavedRemoteObservationProgress {
                next_after: page.next_after,
                reached_end: page.reached_end,
                unavailable_candidates: unavailable,
            })
        })
    }

    fn complete_queued_cancellation(
        &self,
        taskrun_id: runne_domain::id::TaskRunId,
        expected_version: u64,
    ) -> runne_provider::ProviderFuture<'_, Result<(), AutomaticTaskRunError>> {
        Box::pin(async move {
            let queued = self.taskruns.complete_queued_cancellation(
                &DaemonAutomaticTaskRuns::runtime_context(),
                CompleteQueuedCancellationInput {
                    taskrun_id,
                    expected_version,
                },
                &self.store,
            );
            match queued {
                Ok(_) => Ok(()),
                Err(runne_application::service::CompleteQueuedCancellationServiceError::Port(
                    runne_application::ports::CompleteQueuedCancellationError::AlreadyClaimed,
                )) => match self.taskruns.complete_claimed_taskrun_cancellation(
                    &DaemonAutomaticTaskRuns::runtime_context(),
                    CompleteClaimedTaskRunCancellationInput { taskrun_id, expected_version },
                    &self.store,
                ) {
                    Ok(_) => Ok(()),
                    Err(runne_application::service::CompleteQueuedCancellationServiceError::Port(
                        runne_application::ports::CompleteQueuedCancellationError::AlreadyClaimed,
                    )) => {
                        match super::exec_taskrun_pre_effect_cancel::settle_pre_effect_cancellation(
                            &self.store,
                            self.text.as_ref(),
                            taskrun_id,
                            expected_version,
                        ) {
                            Ok(true) => return Ok(()),
                            Ok(false) => {}
                            Err(()) => return Err(AutomaticTaskRunError::Uncertain),
                        }
                        match super::exec_taskrun_pre_effect_cancel::settle_no_admission_cancellation(
                            &self.store,
                            self.text.as_ref(),
                            taskrun_id,
                            expected_version,
                        ) {
                            Ok(true) => return Ok(()),
                            Ok(false) => {}
                            Err(()) => return Err(AutomaticTaskRunError::Uncertain),
                        }
                        match self.provider.as_ref() {
                        Some(provider) => match provider
                            .settle_claimed_cancellation(taskrun_id, expected_version)
                            .await
                        {
                            Ok(true) => Ok(()),
                            _ => Err(AutomaticTaskRunError::Uncertain),
                        },
                        None => Err(AutomaticTaskRunError::Uncertain),
                        }
                    }
                    Err(_) => Err(AutomaticTaskRunError::Uncertain),
                },
                Err(_) => Err(AutomaticTaskRunError::Uncertain),
            }
        })
    }
}
