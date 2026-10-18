use super::helpers::complete_cancelled;
use crate::application::exec_taskrun_worker::DaemonAutomaticTaskRuns;
use runne_application::ports::LoadedStream;
use runne_platform::process_managed_area::LinuxManagedArea;
use runne_store::store::{
    LocalCommandAttemptState, LocalCommandCancellationStopEvidence, LocalCommandPermissionRoute,
    LocalCommandRecoveryCandidate,
};
use std::time::Duration;

/// Recovers one durably `Cancelling` local command attempt whose exact managed
/// area was reopened: stop the child first, then either complete the
/// cancellation exactly once with strict proof, or settle into the canonical
/// unconfirmed state — never a fabricated completion.
///
/// Diagnostics stay branch-specific: `complete_route_lookup` (route/evidence
/// reads), `complete_current` (CurrentPermission completion unit of work),
/// `complete_legacy` (legacy completion service), `complete_stop_conflict`
/// (a factual terminal attempt whose permission stop proof is missing or owned
/// by a non-cancellation stop class — an integrity conflict that must stay
/// visible instead of being relabeled unconfirmed). Insufficient evidence for
/// a still-resolvable attempt is not corruption: the child is stopped, the
/// area is proven empty, and the attempt settles as `stop_unconfirmed`.
pub(super) fn recover_cancelling(
    worker: &DaemonAutomaticTaskRuns,
    candidate: &LocalCommandRecoveryCandidate,
    stream: LoadedStream,
    area: LinuxManagedArea,
) -> Result<(), &'static str> {
    let stop_already_proven = matches!(
        candidate.state,
        LocalCommandAttemptState::Completed | LocalCommandAttemptState::Cancelled
    );
    let route = worker
        .store
        .local_command_permission_route(candidate.identity.taskrun_id)
        .map_err(|error| {
            tracing::warn!(
                ?error,
                stage = "complete_route_lookup",
                "cancellation route lookup failed"
            );
            "complete_route_lookup"
        })?;
    let current_permission = matches!(route, LocalCommandPermissionRoute::CurrentPermission);
    let completion_blocked = current_permission
        && !matches!(
            worker
                .store
                .local_command_cancellation_stop_evidence(
                    candidate.identity.taskrun_id,
                    candidate.identity.attempt_id,
                )
                .map_err(|error| {
                    tracing::warn!(
                        ?error,
                        stage = "complete_route_lookup",
                        "cancellation stop evidence read failed"
                    );
                    "complete_route_lookup"
                })?,
            LocalCommandCancellationStopEvidence::Proven
                | LocalCommandCancellationStopEvidence::Recordable
        );
    if !stop_already_proven {
        worker
            .store
            .request_local_command_stop_recovery(candidate, &worker.node_id, worker.epoch)
            .map_err(|_| "request_stop")?;
    }
    if area.terminate(Duration::from_secs(2)).is_err()
        || area.is_populated().map_err(|_| "check_area")?
    {
        worker
            .store
            .mark_local_command_recovery_unconfirmed(candidate, &worker.node_id, worker.epoch)
            .map_err(|_| "mark_unconfirmed")?;
        return Ok(());
    }
    if completion_blocked {
        // The child is stopped and the area was proven terminable; without
        // provable cancellation stop evidence no completion may be claimed.
        if stop_already_proven {
            return Err("complete_stop_conflict");
        }
        area.prove_empty().map_err(|_| "prove_empty")?;
        worker
            .store
            .mark_local_command_recovery_unconfirmed(candidate, &worker.node_id, worker.epoch)
            .map_err(|_| "mark_unconfirmed")?;
        return Ok(());
    }
    if !stop_already_proven {
        let empty = area.prove_empty().map_err(|_| "prove_empty")?;
        worker
            .store
            .confirm_local_command_stopped_recovery(candidate, &worker.node_id, worker.epoch, empty)
            .map_err(|_| "confirm_stop")?;
    }
    let empty = area.prove_empty().map_err(|_| "prove_empty")?;
    if current_permission {
        worker
            .store
            .complete_local_command_cancellation_recovery(
                candidate,
                &worker.node_id,
                worker.epoch,
                empty,
            )
            .map_err(|error| {
                tracing::warn!(
                    ?error,
                    stage = "complete_current",
                    "current-permission cancellation completion failed"
                );
                "complete_current"
            })?;
    } else {
        complete_cancelled(
            &worker.taskruns,
            &worker.store,
            candidate,
            stream.current_version,
        )
        .map_err(|_| "complete_legacy")?;
    }
    area.remove_empty().map_err(|_| "remove_area")
}

#[cfg(all(test, feature = "desktop-protected", target_os = "linux"))]
#[path = "cancellation_tests.rs"]
mod tests;
