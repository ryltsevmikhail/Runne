use super::DaemonError;
use super::exec_taskrun_worker::DaemonAutomaticTaskRuns;
#[cfg(any(test, not(feature = "desktop-protected")))]
use super::{
    ConversationTextCommandService, DaemonCanonicalProviderService, SqliteTaskRunService,
    StoreTransaction,
};
use runne_application::ports::TaskRunQueueCandidate;
use runne_application::ports::{
    ConversationRepository, EventStore, TaskRunNoEffectScanRequest, TaskRunNoEffectScanner,
};
use runne_runtime::taskrun_auto_worker::AutomaticTaskRunError;
use std::sync::Arc;
#[cfg(any(test, not(feature = "desktop-protected")))]
use std::sync::atomic::AtomicU64;

#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "exec_taskrun_recovery/d2_failure_projection.rs"]
mod d2_failure_projection;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "exec_taskrun_recovery/d2_projection.rs"]
mod d2_projection;
#[cfg(all(feature = "desktop-protected", target_os = "linux"))]
#[path = "exec_taskrun_recovery/local.rs"]
mod local;

impl DaemonAutomaticTaskRuns {
    pub(super) fn recover_pre_effect_cancellations(&self) -> Result<usize, AutomaticTaskRunError> {
        let no_admission =
            super::exec_taskrun_pre_effect_cancel::recover_all_no_admission_cancellations(
                &self.store,
                self.text.as_ref(),
            )
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let pre_effect =
            super::exec_taskrun_pre_effect_cancel::recover_all_pre_effect_cancellations(
                &self.store,
                self.text.as_ref(),
            )
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        no_admission
            .checked_add(pre_effect)
            .ok_or(AutomaticTaskRunError::Uncertain)
    }

    pub(crate) fn submit_selection_before_claim(
        &self,
        candidate: TaskRunQueueCandidate,
    ) -> Result<
        (
            Option<String>,
            Option<runne_domain::task_run::SelectedProviderProfile>,
        ),
        AutomaticTaskRunError,
    > {
        let stream = self
            .store
            .load_task_run(candidate.taskrun_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        if stream.current_version != candidate.current_version {
            return Err(AutomaticTaskRunError::Unavailable);
        }
        let task = runne_domain::task_run::TaskRun::replay(&stream.events)
            .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        let snapshot = task.snapshot_v1();
        if snapshot.state() != runne_domain::task_run::TaskRunState::Queued {
            return Err(AutomaticTaskRunError::Unavailable);
        }
        let conversation_id = snapshot
            .conversation_id()
            .ok_or(AutomaticTaskRunError::Uncertain)?;
        let workspace_id = snapshot
            .workspace_id()
            .ok_or(AutomaticTaskRunError::Uncertain)?;
        let conversation_stream = self
            .store
            .load_conversation(conversation_id)
            .map_err(|_| AutomaticTaskRunError::Unavailable)?;
        let conversation =
            runne_domain::conversation::Conversation::replay(&conversation_stream.events)
                .map_err(|_| AutomaticTaskRunError::Uncertain)?;
        if conversation.workspace_id != workspace_id {
            return Err(AutomaticTaskRunError::Uncertain);
        }
        if conversation.active_generation().is_some() {
            // Do not claim an accepted TaskRun while another text generation
            // owns the conversation writer. A later queue scan retries it.
            return Err(AutomaticTaskRunError::Unavailable);
        }
        let input = snapshot.input().ok_or(AutomaticTaskRunError::Uncertain)?;
        Ok((
            input.requested_model().map(str::to_owned),
            input.selected_profile().cloned(),
        ))
    }

    pub(super) fn recover_old_no_effect(&self) -> Result<usize, AutomaticTaskRunError> {
        let mut cursor = None;
        let mut settled = 0;
        loop {
            let request =
                TaskRunNoEffectScanRequest::new(cursor, 128, self.node_id.clone(), self.epoch)
                    .ok_or(AutomaticTaskRunError::Unavailable)?;
            let page = self
                .store
                .scan_no_effect_assignments(request)
                .map_err(|_| AutomaticTaskRunError::Unavailable)?;
            for candidate in page.candidates {
                self.release_before_effect(candidate.identity, candidate.current_version)?;
                settled += 1;
            }
            if page.reached_end {
                return Ok(settled);
            }
            cursor = page.next_cursor;
            if cursor.is_none() {
                return Err(AutomaticTaskRunError::Uncertain);
            }
        }
    }
}

#[cfg(any(
    not(feature = "desktop-protected"),
    all(test, not(target_os = "linux"))
))]
pub(crate) fn automatic_taskrun_service(
    store: StoreTransaction,
    taskruns: Arc<SqliteTaskRunService>,
    text: Arc<dyn ConversationTextCommandService>,
    provider: Option<Arc<DaemonCanonicalProviderService>>,
    authority_id: [u8; 16],
    epoch: u64,
    current_epoch: Arc<AtomicU64>,
) -> Result<Arc<dyn runne_runtime::taskrun_auto_worker::AutomaticTaskRunService>, DaemonError> {
    let worker = Arc::new(DaemonAutomaticTaskRuns::new(
        store,
        taskruns,
        text,
        provider,
        runne_application::ports::ExecutionNodeId(uuid::Uuid::from_bytes(authority_id).to_string()),
        epoch,
        current_epoch,
    ));
    finish_automatic_taskrun_service(worker)
}

#[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
pub(crate) fn provider_only_taskrun_service_for_test(
    store: StoreTransaction,
    taskruns: Arc<SqliteTaskRunService>,
    text: Arc<dyn ConversationTextCommandService>,
    provider: Option<Arc<DaemonCanonicalProviderService>>,
    authority_id: [u8; 16],
    epoch: u64,
    current_epoch: Arc<AtomicU64>,
) -> Result<Arc<dyn runne_runtime::taskrun_auto_worker::AutomaticTaskRunService>, DaemonError> {
    let worker = Arc::new(DaemonAutomaticTaskRuns::new_provider_only_test_fixture(
        store,
        taskruns,
        text,
        provider,
        runne_application::ports::ExecutionNodeId(uuid::Uuid::from_bytes(authority_id).to_string()),
        epoch,
        current_epoch,
    ));
    finish_automatic_taskrun_service(worker)
}

#[cfg(feature = "desktop-protected")]
pub(crate) fn automatic_taskrun_service_with_root(
    config: super::exec_taskrun_worker::ProtectedTaskRunWorkerConfig,
) -> Result<Arc<dyn runne_runtime::taskrun_auto_worker::AutomaticTaskRunService>, DaemonError> {
    let worker = Arc::new(DaemonAutomaticTaskRuns::new_with_root(config));
    finish_automatic_taskrun_service(worker)
}

fn finish_automatic_taskrun_service(
    worker: Arc<DaemonAutomaticTaskRuns>,
) -> Result<Arc<dyn runne_runtime::taskrun_auto_worker::AutomaticTaskRunService>, DaemonError> {
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    #[cfg(test)]
    if worker.provider_only_test_fixture {
        worker
            .verify_provider_only_fixture_has_no_local_attempts()
            .map_err(|stage| DaemonError::Bootstrap(stage.into()))?;
    } else {
        worker.recover_local_command_effects().map_err(|stage| {
            tracing::warn!(stage, "local command startup recovery failed");
            DaemonError::Bootstrap(format!(
                "reconcile retained local-command attempts: {stage}"
            ))
        })?;
    }
    #[cfg(all(feature = "desktop-protected", target_os = "linux", not(test)))]
    worker.recover_local_command_effects().map_err(|stage| {
        tracing::warn!(stage, "local command startup recovery failed");
        DaemonError::Bootstrap(format!(
            "reconcile retained local-command attempts: {stage}"
        ))
    })?;
    let recovered = worker
        .recover_old_no_effect()
        .map_err(|_| DaemonError::Bootstrap("settle old TaskRun assignments".into()))?;
    if recovered > 0 {
        tracing::info!(
            assignments = recovered,
            "released old-epoch TaskRuns proven never dispatched"
        );
    }
    worker
        .recover_pre_effect_cancellations()
        .map_err(|_| DaemonError::Bootstrap("settle cancelled pre-effect rejections".into()))?;
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    worker.recover_d2_terminal_projections().map_err(|stage| {
        tracing::warn!(stage, "D2 terminal projection recovery failed");
        DaemonError::Bootstrap("recover exact D2 terminal projections".into())
    })?;
    #[cfg(all(feature = "desktop-protected", target_os = "linux"))]
    worker.recover_d2_failure_projections().map_err(|stage| {
        tracing::warn!(stage, "D2 failure projection recovery failed");
        DaemonError::Bootstrap("recover truthful D2 failure projections".into())
    })?;
    Ok(worker)
}
