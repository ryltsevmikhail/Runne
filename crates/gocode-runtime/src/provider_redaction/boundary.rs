use gocode_application::prohibited_content::{
    CanonicalContentBoundary, ContentDisposition, ProhibitedContentPort,
};
use gocode_provider::{
    CredentialMatcher, DispatchAttemptId, ProviderStreamEvent, ProviderStreamEventKind,
    ScannerError, ScannerTerminalDisposition, TailBinding, WithheldTailStore,
};
use zeroize::Zeroizing;

use super::surfaces::inspect_event_surfaces;
use super::{ProviderRedactionError, ProviderRedactionRecovery, ScannerRecoveryPersistence};
use crate::provider_execution::ProviderEventJournalContext;

const SCANNER_ALGORITHM_VERSION: u32 = 1;

/// Result from the mandatory scanner boundary before encrypted journal append.
pub enum PreJournalProviderEvent {
    /// Scanner-approved event containing only safe text bytes.
    Append(ProviderStreamEvent),
    /// Publication-blocking terminal scanner state.
    Terminal(ScannerTerminalDisposition),
}

/// Mandatory runtime port applied to every authoritative provider-event append.
pub trait ProviderEventRedaction: Send + Sync {
    /// Scans or classifies one provider event before journal serialization.
    fn scan_before_journal(
        &self,
        context: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<PreJournalProviderEvent, ProviderRedactionError>;

    /// Returns the terminal scanner state used to gate replay/outbox publication.
    fn terminal_disposition(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<Option<ScannerTerminalDisposition>, ProviderRedactionError>;
}

/// Durable scanner boundary backed only by native tail bytes and metadata persistence.
pub struct ProviderEventRedactionBoundary<'a, T: ?Sized, P: ?Sized, M: ?Sized> {
    tails: &'a T,
    persistence: &'a P,
    matcher: &'a M,
}

impl<'a, T: ?Sized, P: ?Sized, M: ?Sized> ProviderEventRedactionBoundary<'a, T, P, M> {
    /// Binds the three mandatory scanner authorities.
    pub const fn new(tails: &'a T, persistence: &'a P, matcher: &'a M) -> Self {
        Self {
            tails,
            persistence,
            matcher,
        }
    }
}

impl<T, P, M> ProviderEventRedaction for ProviderEventRedactionBoundary<'_, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    fn scan_before_journal(
        &self,
        context: &ProviderEventJournalContext,
        event: &ProviderStreamEvent,
    ) -> Result<PreJournalProviderEvent, ProviderRedactionError> {
        match event.kind() {
            ProviderStreamEventKind::TextDelta { text } => {
                let mut session = self.session(context)?;
                let mut safe = Zeroizing::new(Vec::new());
                session.ingest(text.as_bytes(), &mut safe)?;
                decision(event.sequence(), &mut session, safe, None)
            }
            ProviderStreamEventKind::Finished {
                disposition,
                reason,
            } => {
                let mut session = self.session(context)?;
                inspect_event_surfaces(&mut session, event.kind())?;
                if let Some(disposition) = session.disposition() {
                    return Ok(PreJournalProviderEvent::Terminal(disposition));
                }
                let mut safe = Zeroizing::new(Vec::new());
                session.complete(&mut safe)?;
                decision(
                    event.sequence(),
                    &mut session,
                    safe,
                    Some((*disposition, reason.clone())),
                )
            }
            ProviderStreamEventKind::ToolCallRequested { .. } => {
                let mut session = self.session(context)?;
                inspect_event_surfaces(&mut session, event.kind())?;
                match session.disposition() {
                    Some(disposition) => Ok(PreJournalProviderEvent::Terminal(disposition)),
                    None => Ok(PreJournalProviderEvent::Append(event.clone())),
                }
            }
            ProviderStreamEventKind::ScannerCompleted { .. }
            | ProviderStreamEventKind::ScannerProgress => Ok(PreJournalProviderEvent::Terminal(
                ScannerTerminalDisposition::Uncertain(
                    gocode_provider::ScannerUncertainReason::RedactionScannerUnavailable,
                ),
            )),
            _ => Ok(PreJournalProviderEvent::Append(event.clone())),
        }
    }

    fn terminal_disposition(
        &self,
        attempt: DispatchAttemptId,
    ) -> Result<Option<ScannerTerminalDisposition>, ProviderRedactionError> {
        self.persistence
            .load(attempt)
            .map(|record| record.and_then(|value| value.disposition()))
            .map_err(|_| ProviderRedactionError::PersistenceUnavailable)
    }
}

impl<T, P, M> ProviderEventRedactionBoundary<'_, T, P, M>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    fn session(
        &self,
        context: &ProviderEventJournalContext,
    ) -> Result<ProviderRedactionRecovery<'_, T, P, M>, ProviderRedactionError> {
        let epoch = self.matcher.epoch().unwrap_or(1);
        let expected = TailBinding::new(
            context.attempt_id,
            context.fencing_token,
            epoch,
            epoch,
            SCANNER_ALGORITHM_VERSION,
            0,
        )
        .map_err(|_| ProviderRedactionError::PersistenceUnavailable)?;
        match self.persistence.load(context.attempt_id) {
            Ok(Some(_)) => ProviderRedactionRecovery::restart(
                expected,
                self.tails,
                self.persistence,
                self.matcher,
            ),
            Ok(None) | Err(_) => ProviderRedactionRecovery::start(
                expected,
                self.tails,
                self.persistence,
                self.matcher,
            ),
        }
    }
}

fn decision<T, P, M>(
    sequence: u64,
    session: &mut ProviderRedactionRecovery<'_, T, P, M>,
    safe: Zeroizing<Vec<u8>>,
    terminal: Option<(
        gocode_provider::ProviderTerminalDisposition,
        gocode_provider::ProviderFinishReason,
    )>,
) -> Result<PreJournalProviderEvent, ProviderRedactionError>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    if let Some(disposition) = session.disposition() {
        if disposition != ScannerTerminalDisposition::Completed {
            return Ok(PreJournalProviderEvent::Terminal(disposition));
        }
    }
    let text = match String::from_utf8(safe.to_vec()) {
        Ok(text) => text,
        Err(_) => {
            session.fail(gocode_provider::ScannerUncertainReason::RedactionScannerUnavailable)?;
            return Ok(PreJournalProviderEvent::Terminal(
                session
                    .disposition()
                    .unwrap_or(ScannerTerminalDisposition::Uncertain(
                        gocode_provider::ScannerUncertainReason::RedactionScannerUnavailable,
                    )),
            ));
        }
    };
    let kind = match terminal {
        Some((disposition, reason)) => ProviderStreamEventKind::ScannerCompleted {
            text,
            disposition,
            reason,
        },
        None if text.is_empty() => ProviderStreamEventKind::ScannerProgress,
        None => ProviderStreamEventKind::TextDelta { text },
    };
    match ProviderStreamEvent::new(sequence, kind) {
        Ok(event) => Ok(PreJournalProviderEvent::Append(event)),
        Err(_) => {
            session.fail(gocode_provider::ScannerUncertainReason::RedactionScannerUnavailable)?;
            Ok(PreJournalProviderEvent::Terminal(
                session
                    .disposition()
                    .unwrap_or(ScannerTerminalDisposition::Uncertain(
                        gocode_provider::ScannerUncertainReason::RedactionScannerUnavailable,
                    )),
            ))
        }
    }
}

/// Credential matcher adapter over the canonical prohibited-content registry.
pub struct ProhibitedContentCredentialMatcher<'a> {
    guard: &'a dyn ProhibitedContentPort,
}

impl<'a> ProhibitedContentCredentialMatcher<'a> {
    /// Pins the canonical prohibited-content registry.
    pub const fn new(guard: &'a dyn ProhibitedContentPort) -> Self {
        Self { guard }
    }
}

impl CredentialMatcher for ProhibitedContentCredentialMatcher<'_> {
    fn epoch(&self) -> Result<u64, ScannerError> {
        disposition_epoch(
            self.guard
                .inspect(CanonicalContentBoundary::CanonicalMutation, b""),
        )
    }

    fn maximum_match_len(&self) -> Result<usize, ScannerError> {
        self.guard
            .maximum_match_len()
            .map_err(|_| ScannerError::MatcherUnavailable)
    }

    fn contains_match(&self, bytes: &[u8]) -> Result<bool, ScannerError> {
        self.guard
            .inspect(CanonicalContentBoundary::CanonicalMutation, bytes)
            .map(|value| matches!(value, ContentDisposition::Prohibited { .. }))
            .map_err(|_| ScannerError::MatcherUnavailable)
    }
}

fn disposition_epoch(
    value: Result<ContentDisposition, gocode_application::prohibited_content::ContentGuardError>,
) -> Result<u64, ScannerError> {
    value
        .map(|value| match value {
            ContentDisposition::Allowed { policy_epoch }
            | ContentDisposition::Prohibited { policy_epoch } => policy_epoch,
        })
        .map_err(|_| ScannerError::MatcherUnavailable)
}
