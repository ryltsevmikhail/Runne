use super::super::saved_remote_recovery::SavedRemoteRecoveryCandidate;
use super::super::*;
use super::SavedRemoteObservationOutcome;
use runne_provider::{
    ProviderFuture, ProviderRecoveryError, ProviderRecoveryRequest, ProviderRemoteCheck,
    ProviderRemotePublicationDisposition, ProviderRemoteResponseStatus,
    ProviderRemoteTerminalArtifact,
};
use runne_runtime::provider_redaction::scan_complete_provider_snapshot;

pub(super) async fn check_saved_response<A: SavedRemoteRecoveryAdapter + ?Sized>(
    adapter: &A,
    candidate: &SavedRemoteRecoveryCandidate,
    request: ProviderRecoveryRequest,
) -> Result<ProviderRemoteCheck, SavedRemoteObservationOutcome> {
    let timeout = std::time::Duration::from_secs(3);
    let deadline = tokio::time::Instant::now() + timeout;
    if candidate.remote_cancel_requested {
        match tokio::time::timeout_at(deadline, adapter.cancel_remote(request.clone())).await {
            Ok(Ok(check)) => return Ok(check),
            Err(_) | Ok(Err(runne_provider::ProviderRecoveryError::Unavailable)) => {
                if !candidate.status_check_supported {
                    return Err(SavedRemoteObservationOutcome::Unknown);
                }
            }
            Ok(Err(runne_provider::ProviderRecoveryError::Unsupported)) => {
                if !candidate.status_check_supported {
                    return Err(SavedRemoteObservationOutcome::Unsupported);
                }
            }
            Ok(Err(_)) => return Err(SavedRemoteObservationOutcome::Unknown),
        }
    }
    if !candidate.status_check_supported {
        return Err(SavedRemoteObservationOutcome::Unsupported);
    }
    tokio::time::timeout_at(deadline, adapter.check_remote_status(request))
        .await
        .map_err(|_| SavedRemoteObservationOutcome::Unknown)?
        .map_err(|error| match error {
            runne_provider::ProviderRecoveryError::Unsupported => {
                SavedRemoteObservationOutcome::Unsupported
            }
            _ => SavedRemoteObservationOutcome::Unknown,
        })
}

pub(super) trait SavedRemoteRecoveryAdapter: Send + Sync {
    fn check_remote_status(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>>;

    fn cancel_remote(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>>;
}

impl SavedRemoteRecoveryAdapter for dyn CanonicalProviderEffect + '_ {
    fn check_remote_status(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        ProviderPort::check_remote_status(self, request)
    }

    fn cancel_remote(
        &self,
        request: ProviderRecoveryRequest,
    ) -> ProviderFuture<'_, Result<ProviderRemoteCheck, ProviderRecoveryError>> {
        ProviderPort::cancel_remote(self, request)
    }
}

pub(super) fn sanitize_remote_terminal(
    prohibited_content: &dyn ProhibitedContentPort,
    _saved: &runne_runtime::provider_execution::RecoveredProviderRemoteAttempt,
    check: ProviderRemoteCheck,
) -> Option<ProviderRemoteCheck> {
    let Some(terminal) = check.terminal() else {
        return Some(check);
    };
    let matcher = ProhibitedContentCredentialMatcher::new(prohibited_content);
    let (safe, publication) = match terminal.publication_disposition() {
        ProviderRemotePublicationDisposition::Rejected(reason) => {
            (None, ProviderRemotePublicationDisposition::Rejected(reason))
        }
        ProviderRemotePublicationDisposition::Allowed => match terminal.output_text() {
            Some(text) if text.len() <= 65_536 => {
                match scan_complete_provider_snapshot(&matcher, text) {
                    Ok(text) => (Some(text), ProviderRemotePublicationDisposition::Allowed),
                    Err(disposition) => (
                        None,
                        ProviderRemotePublicationDisposition::Rejected(disposition),
                    ),
                }
            }
            Some(_) => (
                None,
                ProviderRemotePublicationDisposition::Rejected(
                    runne_provider::ScannerTerminalDisposition::OutputLimitExceeded,
                ),
            ),
            None if matches!(
                terminal.status(),
                ProviderRemoteResponseStatus::Completed { .. }
            ) =>
            {
                (
                    None,
                    ProviderRemotePublicationDisposition::Rejected(
                        runne_provider::ScannerTerminalDisposition::Uncertain(
                            runne_provider::ScannerUncertainReason::RedactionScannerUnavailable,
                        ),
                    ),
                )
            }
            None => (None, ProviderRemotePublicationDisposition::Allowed),
        },
    };
    let safe_terminal = ProviderRemoteTerminalArtifact::new_with_publication_disposition(
        terminal.response_id().clone(),
        terminal.status().clone(),
        safe,
        publication,
    )
    .ok()?;
    let proof = check.operation_proof()?.clone();
    let operation = proof.operation();
    ProviderRemoteCheck::new_authorized(
        check.binding(),
        check.response_id().clone(),
        check.status().clone(),
        Some(safe_terminal),
        operation,
        proof,
    )
    .ok()
}
