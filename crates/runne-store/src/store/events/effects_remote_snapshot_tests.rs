#[cfg(test)]
mod projection_tests {
    use super::*;
    use runne_application::provider::{
        ProviderRemoteAccountingProjection as Accounting, ProviderRemoteAttemptBinding,
        ProviderRemoteCredentialProjection, ProviderRemoteEffectsSnapshot,
        ProviderRemoteGrantProjection, ProviderRemoteLocalDisposition,
        ProviderRemoteObservationProjection,
    };
    use runne_domain::id::{AttemptId, TaskRunId};
    use runne_provider::{
        DispatchAttemptId, ProviderRemotePublicationDisposition, ProviderRemoteResponseStatus,
        ProviderUsage,
    };

    fn snapshot(usage: Option<ProviderUsage>) -> ProviderRemoteEffectsSnapshot {
        let binding = ProviderRemoteAttemptBinding {
            taskrun_id: TaskRunId::from_bytes([1; 16]),
            taskrun_attempt_id: AttemptId::from_bytes([2; 16]),
            dispatch_attempt_id: DispatchAttemptId::from_bytes([3; 16]),
            provider_id: "openai-background".into(),
            credential_realm: "openai-background".into(),
            profile_id: "historical-profile".into(),
            profile_digest: [4; 32],
            pricing_digest: [5; 32],
            semantic_digest: [6; 32],
            prepared_digest: [7; 32],
            request_digest: [8; 32],
            runtime_authority_id: [9; 16],
            database_generation: 1,
            runtime_generation: 1,
            fencing_token: 1,
        };
        let fact = runne_application::provider::ProviderRemoteAuthenticatedTerminalFact::new(
            ProviderRemoteResponseStatus::Completed { usage },
            ProviderRemotePublicationDisposition::Allowed,
            Some([10; 32]),
        )
        .unwrap();
        ProviderRemoteEffectsSnapshot {
            binding,
            fact: Some(fact),
            observation: ProviderRemoteObservationProjection::NotObserved,
            local_disposition: ProviderRemoteLocalDisposition::AcceptedCancellationClosed,
            accounting: Accounting::Unknown,
            secondary_grant: ProviderRemoteGrantProjection::Active {
                authority_revision: 1,
            },
            credential: ProviderRemoteCredentialProjection::Unavailable,
            successor_eligibility: SuccessorEligibilityV1::Blocked,
        }
    }

    #[test]
    fn completed_remote_fact_does_not_become_cancelled_when_local_cancel_closed() {
        let usage = ProviderUsage::new(5, 3, 1, 1).unwrap();
        let snapshot = snapshot(Some(usage));
        let projected = project_remote_effect(Some(&snapshot), true, false);
        assert_eq!(projected.outcome, RemoteOutcome::Completed);
        assert_eq!(projected.cancellation, RemoteCancel::Unconfirmed);
        assert_eq!(
            projected.publication,
            runne_api::RemotePublicationV1::Withheld
        );
        assert_eq!(projected.accounting, runne_api::RemoteAccountingV1::Unknown);
        assert_eq!(projected.usage_known, Some(true));
    }

    #[test]
    fn missing_usage_is_separate_from_unknown_pricing() {
        let snapshot = snapshot(None);
        let projected = project_remote_effect(Some(&snapshot), false, false);
        assert_eq!(projected.outcome, RemoteOutcome::Completed);
        assert_eq!(projected.accounting, runne_api::RemoteAccountingV1::Unknown);
        assert_eq!(projected.usage_known, Some(false));
    }

    fn nonterminal_snapshot(
        observation: ProviderRemoteObservationProjection,
    ) -> ProviderRemoteEffectsSnapshot {
        let mut snapshot = snapshot(None);
        snapshot.fact = None;
        snapshot.observation = observation;
        snapshot
    }

    #[test]
    fn fresh_nonterminal_pending_projects_running_without_terminal_facts() {
        let snapshot = nonterminal_snapshot(ProviderRemoteObservationProjection::Pending);
        let projected = project_remote_effect(Some(&snapshot), false, false);
        assert_eq!(projected.outcome, RemoteOutcome::Running);
        assert_eq!(projected.cancellation, RemoteCancel::NotRequested);
        assert_eq!(
            projected.publication,
            runne_api::RemotePublicationV1::Unknown
        );
        assert_eq!(projected.accounting, runne_api::RemoteAccountingV1::Unknown);
        assert_eq!(projected.usage_known, None);
    }

    #[test]
    fn accepted_cancel_without_remote_terminal_projects_unconfirmed() {
        let snapshot = nonterminal_snapshot(ProviderRemoteObservationProjection::Pending);
        let projected = project_remote_effect(Some(&snapshot), true, false);
        assert_eq!(projected.outcome, RemoteOutcome::Running);
        assert_eq!(projected.cancellation, RemoteCancel::Unconfirmed);
        assert_eq!(projected.usage_known, None);
    }

    #[test]
    fn unknown_or_absent_observation_stays_unknown() {
        let unknown = nonterminal_snapshot(ProviderRemoteObservationProjection::Unknown);
        let projected = project_remote_effect(Some(&unknown), false, false);
        assert_eq!(projected.outcome, RemoteOutcome::Unknown);
        assert_eq!(projected.cancellation, RemoteCancel::NotRequested);

        let absent = project_remote_effect(None, true, false);
        assert_eq!(absent.outcome, RemoteOutcome::Unknown);
        assert_eq!(absent.cancellation, RemoteCancel::Unconfirmed);
    }
}
