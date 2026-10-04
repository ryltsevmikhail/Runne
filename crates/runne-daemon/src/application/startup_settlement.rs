//! X2 restart settlement: closes text generations left in the durable
//! `Started` phase by a dead runtime instance.
//!
//! Workers do not survive a restart, so a `Started` receipt observed at boot
//! is by construction orphaned. Only provably effect-free orphans (no durable
//! provider dispatch attempt for the coordinating task run) are settled —
//! as a terminal `interrupted_by_restart` rejection through the normal
//! terminal commit path, which keeps fingerprints, idempotency receipts and
//! the event integrity chain exact. Generations with a dispatch attempt stay
//! untouched: their outcome may be uncertain and remains blocked pending
//! provider reconciliation (plan 18 §D1.3/X2).

use super::*;
use runne_application::commands::{ConversationTextCompletion, FinishConversationTextInput};
use runne_application::ports::ApplicationCommandContext;
use runne_application::ports::RuntimeAuthorityId;

pub(in crate::application) fn settle_interrupted_text_generations(
    connection: &rusqlite::Connection,
    service: &Arc<dyn ConversationTextCommandService>,
    authority: &RuntimeAuthorityId,
) -> Result<usize, DaemonError> {
    let orphans = runne_store::orphan_settlement::scan_provably_effect_free_started_generations(
        connection, authority,
    )
    .map_err(|error| {
        DaemonError::Bootstrap(format!("scan orphaned text generations: {error:?}"))
    })?;
    let mut settled = 0usize;
    for orphan in orphans {
        let scope =
            runne_store::orphan_settlement::decode_command_scope(connection, orphan.command_id)
                .map_err(|error| {
                    DaemonError::Bootstrap(format!(
                        "decode settlement scope for {}: {error:?}",
                        orphan.command_id
                    ))
                })?;
        let actor = runne_domain::event::Actor::new("runne-restart-settlement")
            .map_err(|_| DaemonError::Bootstrap("settlement actor".to_owned()))?;
        let context = ApplicationCommandContext {
            command_id: orphan.command_id,
            idempotency_key: orphan.idempotency_key,
            principal_id: scope.principal_id,
            actor,
        };
        service
            .finish_text(
                &context,
                FinishConversationTextInput {
                    original: orphan.original,
                    started: orphan.receipt,
                    completion: ConversationTextCompletion::Rejected {
                        reason: runne_domain::conversation::GenerationFailureReason::InterruptedByRestart,
                    },
                },
            )
            .map_err(|error| {
                DaemonError::Bootstrap(format!(
                    "settle interrupted generation {}: {error:?}",
                    orphan.command_id
                ))
            })?;
        settled += 1;
    }
    Ok(settled)
}

#[cfg(test)]
mod tests;
