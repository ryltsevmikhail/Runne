use gocode_provider::{
    CredentialMatcher, ProviderFinishReason, ProviderStreamEventKind, WithheldTailStore,
};

use super::{ProviderRedactionError, ProviderRedactionRecovery, ScannerRecoveryPersistence};

/// Inspects every provider-controlled string that can carry credential bytes
/// while preserving the original structured event when all surfaces are safe.
pub(super) fn inspect_event_surfaces<T, P, M>(
    session: &mut ProviderRedactionRecovery<'_, T, P, M>,
    kind: &ProviderStreamEventKind,
) -> Result<(), ProviderRedactionError>
where
    T: WithheldTailStore + ?Sized,
    P: ScannerRecoveryPersistence + ?Sized,
    M: CredentialMatcher + ?Sized,
{
    match kind {
        ProviderStreamEventKind::ToolCallRequested {
            call_id,
            tool_name,
            arguments_json,
        } => {
            for surface in [
                call_id.as_bytes(),
                tool_name.as_bytes(),
                arguments_json.as_bytes(),
            ] {
                session.inspect_atomic_surface(surface)?;
            }
        }
        ProviderStreamEventKind::Finished {
            reason: ProviderFinishReason::Unknown { raw },
            ..
        } => session.inspect_atomic_surface(raw.as_bytes())?,
        ProviderStreamEventKind::Started
        | ProviderStreamEventKind::TextDelta { .. }
        | ProviderStreamEventKind::Usage { .. }
        | ProviderStreamEventKind::UsageUnavailable
        | ProviderStreamEventKind::Finished { .. }
        | ProviderStreamEventKind::ScannerCompleted { .. }
        | ProviderStreamEventKind::ScannerProgress => {}
    }
    Ok(())
}
