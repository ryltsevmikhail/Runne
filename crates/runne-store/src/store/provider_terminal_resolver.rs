use super::StoreTransaction;
use crate::codec::{IdempotencyScopeCodec, StoreCodec, TextGenerationReceiptCodec};
use runne_application::commands::BeginConversationTextInput;
use runne_application::ports::{PrincipalId, TextGenerationPhase};
use runne_application::provider::ProviderTerminalOutboxRecord;
use runne_domain::conversation::ConversationEvent;
use runne_runtime::provider_execution::{
    ProviderTerminalConversationResolveError, ProviderTerminalConversationResolver,
    RecoveredProviderConversationCommand,
};
use rusqlite::{OptionalExtension, params};

mod command_proof;
mod no_output;
mod receipt;
mod remote_artifact;
mod unknown_cancellation;

impl ProviderTerminalConversationResolver for StoreTransaction {
    fn resolve_provider_terminal_conversation(
        &self,
        record: &ProviderTerminalOutboxRecord,
    ) -> Result<RecoveredProviderConversationCommand, ProviderTerminalConversationResolveError>
    {
        let mut reader = self
            .inner
            .reader
            .lock()
            .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
        let tx = reader
            .transaction()
            .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
        let stream =
            super::conversation::load_conversation_from_connection(&tx, record.conversation_id)
                .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
        let event = stream
            .events
            .iter()
            .find(|event| {
                matches!(
                    event.payload(),
                    ConversationEvent::UserMessageAppended {
                        taskrun_id,
                        attempt_id,
                        ..
                    } if *taskrun_id == record.taskrun_id
                        && *attempt_id == record.execution_attempt_id
                )
            })
            .ok_or(ProviderTerminalConversationResolveError::Conflict)?;
        let ConversationEvent::UserMessageAppended { text, .. } = event.payload() else {
            return Err(ProviderTerminalConversationResolveError::Conflict);
        };
        let (message_id, event_taskrun_id, event_attempt_id) = match event.payload() {
            ConversationEvent::UserMessageAppended {
                message_id,
                taskrun_id,
                attempt_id,
                ..
            } => (*message_id, *taskrun_id, *attempt_id),
            _ => return Err(ProviderTerminalConversationResolveError::Conflict),
        };
        let expected_version = event
            .sequence()
            .checked_sub(1)
            .ok_or(ProviderTerminalConversationResolveError::Conflict)?;
        let command_id = *event.command_id();
        let idempotency_key = event.idempotency_key().clone();
        let actor = event.actor().clone();
        let (scope_bytes, stored): (Vec<u8>, Vec<u8>) = tx
            .query_row(
                "SELECT idempotency_scope_bytes, command_outcome FROM command_receipts
                 WHERE command_id = ?1 AND idempotency_key = ?2",
                params![command_id.as_bytes(), idempotency_key.as_str().as_bytes()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
        let scope = IdempotencyScopeCodec
            .decode(&scope_bytes)
            .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
        let mut started = TextGenerationReceiptCodec
            .decode(&stored)
            .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
        receipt::validate_identity(
            &started,
            record,
            message_id,
            event_taskrun_id,
            event_attempt_id,
        )?;
        receipt::validate_phase_version(&started, event.sequence())?;
        command_proof::verify(
            &tx,
            command_proof::CommandProofExpectation {
                record,
                scope: &scope,
                command_id,
                key: &idempotency_key,
                expected_version,
                text,
                store: self,
            },
        )?;
        if let Some(recovered) = remote_artifact::resolve_accepted_cancellation(
            &tx,
            record,
            self,
            command_id,
            &idempotency_key,
            &actor,
            expected_version,
            text,
            &started,
        )? {
            tx.commit()
                .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
            return Ok(recovered);
        }
        let audit = remote_artifact::resolve_audit_only(
            &tx,
            record,
            self,
            command_id,
            &idempotency_key,
            &actor,
            expected_version,
            text,
            &started,
        )?;
        if let Some(recovered) = audit {
            return Ok(recovered);
        }
        let mut terminal_cancellation = None;
        if started.phase == TextGenerationPhase::Started {
            match super::taskrun_started_generation::classify_started_generation_taskrun(
                &tx,
                &started,
                &BeginConversationTextInput {
                    conversation_id: record.conversation_id,
                    expected_version,
                    text: text.clone(),
                },
                command_id,
                &idempotency_key,
                &scope,
                &self.runtime_authority_id,
            )
            .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?
            {
                super::taskrun_started_generation::StartedGenerationTaskRunState::Running => {}
                super::taskrun_started_generation::StartedGenerationTaskRunState::PendingCancellation => {
                    ensure_provider_cancel_fence(&tx, record)?;
                    let version: i64 = tx.query_row(
                        "SELECT current_version FROM aggregate_streams WHERE aggregate_type=1 AND aggregate_id=?1",
                        [record.taskrun_id.as_bytes()], |row| row.get(0),
                    ).map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
                    let cancellation_taskrun_version = u64::try_from(version)
                        .map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
                    if cancellation_taskrun_version != started.taskrun_version.checked_add(1)
                        .ok_or(ProviderTerminalConversationResolveError::Conflict)?
                    {
                        return Err(ProviderTerminalConversationResolveError::Conflict);
                    }
                    terminal_cancellation = Some(match record.source {
                        runne_application::provider::ProviderTerminalOutboxSource::UnknownJournal {
                            commitment,
                        } => unknown_cancellation::resolve(
                            &tx,
                            record,
                            commitment,
                            cancellation_taskrun_version,
                        )?,
                        runne_application::provider::ProviderTerminalOutboxSource::StreamJournal => {
                            let marker: Option<(i64, Vec<u8>)> = tx.query_row(
                                "SELECT disposition, a.settlement_digest
                                 FROM provider_terminal_dispositions d
                                 JOIN provider_dispatch_attempts a ON a.attempt_id=d.dispatch_attempt_id
                                 WHERE d.dispatch_attempt_id=?1",
                                [record.attempt_id.as_bytes()],
                                |row| Ok((row.get(0)?, row.get(1)?)),
                            ).optional().map_err(|_| ProviderTerminalConversationResolveError::Conflict)?;
                            match marker {
                                None => return Err(ProviderTerminalConversationResolveError::Deferred),
                                Some((1, digest)) if digest == record.settlement_digest => {}
                                Some(_) => return Err(ProviderTerminalConversationResolveError::Conflict),
                            }
                            runne_runtime::provider_execution::RecoveredProviderTerminalCancellation::StreamJournal(
                                runne_application::ports::ProviderTerminalCancellationEvidence {
                                    dispatch_attempt_id: *record.attempt_id.as_bytes(),
                                    disposition: runne_provider::ProviderTerminalDisposition::Completed,
                                    settlement_digest: record.settlement_digest,
                                    cancellation_taskrun_version,
                                },
                            )
                        }
                        runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact { .. } => {
                            return Err(ProviderTerminalConversationResolveError::Conflict);
                        }
                    });
                }
            }
        } else if started.phase == TextGenerationPhase::Rejected
            && matches!(
                record.source,
                runne_application::provider::ProviderTerminalOutboxSource::RemoteArtifact { .. }
            )
        {
            let Some(recovered) =
                remote_artifact::resolve_closed_cancellation(&tx, record, self, &started)?
            else {
                return Err(ProviderTerminalConversationResolveError::Conflict);
            };
            started = recovered.started;
            terminal_cancellation = Some(
                runne_runtime::provider_execution::RecoveredProviderTerminalCancellation::RemoteArtifact(
                    recovered.evidence,
                ),
            );
        } else if started.phase == TextGenerationPhase::Rejected {
            terminal_cancellation = Some(
                runne_runtime::provider_execution::RecoveredProviderTerminalCancellation::StreamJournal(
                    resolve_stream_journal_cancellation(&tx, record, &stream, &started)?,
                ),
            );
        }
        tx.commit()
            .map_err(|_| ProviderTerminalConversationResolveError::Unavailable)?;
        Ok(RecoveredProviderConversationCommand {
            context: runne_application::ports::ApplicationCommandContext {
                command_id,
                idempotency_key,
                principal_id: PrincipalId(record.principal_id.clone()),
                actor,
            },
            original: BeginConversationTextInput {
                conversation_id: record.conversation_id,
                expected_version,
                text: text.clone(),
            },
            started,
            terminal_cancellation,
            audit_only: false,
        })
    }

    fn resolve_remote_terminal_without_output(
        &self,
        attempt_id: runne_provider::DispatchAttemptId,
    ) -> Result<
        Option<runne_runtime::provider_execution::RecoveredProviderNoOutputCommand>,
        ProviderTerminalConversationResolveError,
    > {
        no_output::resolve(self, attempt_id)
    }
}

include!("provider_terminal_resolver/cancel_fence.rs");
