// Durable delivery evidence for one task-run attempt.
//
// A claim that failed before the first provider round has no provider result.
// Projecting that state as an unknown remote effect keeps a safe runtime exit
// blocked even though no delivery was ever issued. Two independent proofs close
// the effect: the dispatch attempt is durably refused before any effect (the
// store's own typed rejection), or none of the three delivery slots exists (the
// same evidence set the cancellation-completion path treats as "the attempt may
// have reached the provider").

/// Evidence slots that would prove provider delivery preparation started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ProviderDeliveryEvidence {
    rejected_before_effect: bool,
    dispatch_intent: bool,
    provider_binding: bool,
    execution_admission: bool,
}

impl ProviderDeliveryEvidence {
    /// Whether the attempt provably stopped before any provider delivery.
    #[must_use]
    pub(super) const fn proves_no_delivery(self) -> bool {
        self.rejected_before_effect
            || !(self.dispatch_intent || self.provider_binding || self.execution_admission)
    }
}

/// Reads the durable delivery evidence for one attempt inside the read transaction.
pub(super) fn provider_delivery_evidence(
    tx: &rusqlite::Transaction<'_>,
    taskrun_id: TaskRunId,
    attempt_id: runne_domain::id::AttemptId,
) -> Result<ProviderDeliveryEvidence, EventStoreError> {
    let (rejected_before_effect, dispatch_intent, provider_binding, execution_admission) = tx
        .query_row(
            "SELECT \
               EXISTS(SELECT 1 FROM provider_execution_admissions admission \
                      JOIN provider_dispatch_attempts dispatch \
                        ON dispatch.attempt_id = admission.dispatch_attempt_id \
                      WHERE admission.taskrun_id=?1 AND admission.execution_attempt_id=?2 \
                        AND dispatch.state = 2), \
               EXISTS(SELECT 1 FROM taskrun_dispatch_intents WHERE taskrun_id=?1 AND attempt_id=?2), \
               EXISTS(SELECT 1 FROM taskrun_provider_bindings WHERE taskrun_id=?1 AND attempt_id=?2), \
               EXISTS(SELECT 1 FROM provider_execution_admissions WHERE taskrun_id=?1 AND execution_attempt_id=?2)",
            params![taskrun_id.as_bytes(), attempt_id.as_bytes()],
            |row| {
                Ok((
                    row.get::<_, bool>(0)?,
                    row.get::<_, bool>(1)?,
                    row.get::<_, bool>(2)?,
                    row.get::<_, bool>(3)?,
                ))
            },
        )
        .map_err(|_| EventStoreError::CorruptData)?;
    Ok(ProviderDeliveryEvidence {
        rejected_before_effect,
        dispatch_intent,
        provider_binding,
        execution_admission,
    })
}

/// Projects the remote effect of a terminal attempt with no delivery evidence.
pub(super) fn project_no_delivery_remote(cancellation_requested: bool) -> RemoteEffectV1 {
    RemoteEffectV1 {
        outcome: RemoteOutcome::NotStarted,
        publication: runne_api::RemotePublicationV1::NotApplicable,
        accounting: runne_api::RemoteAccountingV1::NotApplicable,
        cancellation: if cancellation_requested {
            RemoteCancel::Unconfirmed
        } else {
            RemoteCancel::NotRequested
        },
        availability: RemoteAvailability::NotConfigured,
        capabilities: RemoteEffectCapabilitiesV1 {
            status_check: false,
            stream_resume: false,
            remote_cancel: false,
        },
        usage_known: None,
    }
}

#[cfg(test)]
mod no_delivery_tests {
    use super::*;

    #[test]
    fn refused_attempt_or_absent_slots_prove_no_delivery() {
        let absent = ProviderDeliveryEvidence {
            rejected_before_effect: false,
            dispatch_intent: false,
            provider_binding: false,
            execution_admission: false,
        };
        assert!(absent.proves_no_delivery());
        let refused = ProviderDeliveryEvidence {
            rejected_before_effect: true,
            dispatch_intent: true,
            provider_binding: true,
            execution_admission: true,
        };
        assert!(refused.proves_no_delivery());
        for evidence in [
            ProviderDeliveryEvidence {
                rejected_before_effect: false,
                dispatch_intent: true,
                provider_binding: false,
                execution_admission: false,
            },
            ProviderDeliveryEvidence {
                rejected_before_effect: false,
                dispatch_intent: false,
                provider_binding: true,
                execution_admission: false,
            },
            ProviderDeliveryEvidence {
                rejected_before_effect: false,
                dispatch_intent: false,
                provider_binding: false,
                execution_admission: true,
            },
        ] {
            assert!(!evidence.proves_no_delivery());
        }
    }

    #[test]
    fn proven_no_delivery_is_not_started_and_never_a_pending_cancellation() {
        let effect = project_no_delivery_remote(false);
        assert_eq!(effect.outcome, RemoteOutcome::NotStarted);
        assert_eq!(effect.cancellation, RemoteCancel::NotRequested);
        assert_eq!(
            effect.publication,
            runne_api::RemotePublicationV1::NotApplicable
        );
        assert_eq!(
            effect.accounting,
            runne_api::RemoteAccountingV1::NotApplicable
        );
    }
}
