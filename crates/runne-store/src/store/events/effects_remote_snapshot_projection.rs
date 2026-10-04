fn project_unknown_source1_effect(
    fact: &runne_application::provider::ProviderUnknownTerminalFact,
    cancellation_requested: bool,
) -> RemoteEffectV1 {
    use runne_provider::ProviderTerminalDisposition as Disposition;
    let outcome = match fact.disposition {
        Disposition::Completed => RemoteOutcome::Completed,
        Disposition::RemoteFailed => RemoteOutcome::Failed,
        Disposition::RemoteIncomplete => RemoteOutcome::Incomplete,
        Disposition::CancelledUncertain => RemoteOutcome::Unknown,
    };
    let publication = if fact.output_was_published && fact.output_was_applied {
        runne_api::RemotePublicationV1::Allowed
    } else if fact.output_digest.is_some() {
        runne_api::RemotePublicationV1::Withheld
    } else {
        runne_api::RemotePublicationV1::NotApplicable
    };
    RemoteEffectV1 {
        outcome,
        publication,
        accounting: runne_api::RemoteAccountingV1::Unknown,
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
        usage_known: Some(fact.usage.is_some()),
    }
}

fn project_remote_effect(
    snapshot: Option<&runne_application::provider::ProviderRemoteEffectsSnapshot>,
    cancellation_requested: bool,
    local_is_selected: bool,
) -> RemoteEffectV1 {
    use runne_application::provider::{
        ProviderRemoteAccountingProjection as Accounting, ProviderRemoteLocalDisposition as Local,
    };
    use runne_provider::ProviderRemoteResponseStatus as Status;
    if local_is_selected {
        return RemoteEffectV1 {
            outcome: RemoteOutcome::NotApplicable,
            publication: runne_api::RemotePublicationV1::NotApplicable,
            accounting: runne_api::RemoteAccountingV1::NotApplicable,
            cancellation: RemoteCancel::NotRequested,
            availability: RemoteAvailability::NotConfigured,
            capabilities: RemoteEffectCapabilitiesV1 {
                status_check: false,
                stream_resume: false,
                remote_cancel: false,
            },
            usage_known: None,
        };
    }
    let Some(snapshot) = snapshot else {
        return project_nonterminal_remote(None, cancellation_requested);
    };
    let Some(fact) = snapshot.fact.as_ref() else {
        return project_nonterminal_remote(Some(snapshot.observation), cancellation_requested);
    };
    let outcome = match fact.status() {
        Status::Completed { .. } => RemoteOutcome::Completed,
        Status::Failed { .. } => RemoteOutcome::Failed,
        Status::Incomplete { .. } => RemoteOutcome::Incomplete,
        Status::Cancelled { .. } => RemoteOutcome::Cancelled,
        Status::Pending | Status::Unknown => RemoteOutcome::Unknown,
    };
    let publication = if fact.publication_disposition()
        == runne_provider::ProviderRemotePublicationDisposition::Allowed
        && snapshot.local_disposition == Local::OutputApplied
    {
        runne_api::RemotePublicationV1::Allowed
    } else if matches!(
        fact.status(),
        Status::Completed { .. }
            | Status::Failed { .. }
            | Status::Incomplete { .. }
            | Status::Cancelled { .. }
    ) {
        runne_api::RemotePublicationV1::Withheld
    } else {
        runne_api::RemotePublicationV1::Unknown
    };
    let accounting = match &snapshot.accounting {
        Accounting::NotApplicable => runne_api::RemoteAccountingV1::NotApplicable,
        Accounting::Unknown => runne_api::RemoteAccountingV1::Unknown,
        Accounting::Known { .. } => runne_api::RemoteAccountingV1::Known,
    };
    let remote_cancelled = matches!(fact.status(), Status::Cancelled { .. });
    let cancellation = if cancellation_requested && remote_cancelled {
        RemoteCancel::Confirmed
    } else if cancellation_requested {
        RemoteCancel::Unconfirmed
    } else {
        RemoteCancel::NotRequested
    };
    RemoteEffectV1 {
        outcome,
        publication,
        accounting,
        cancellation,
        availability: RemoteAvailability::Unknown,
        capabilities: RemoteEffectCapabilitiesV1 {
            status_check: false,
            stream_resume: false,
            remote_cancel: false,
        },
        usage_known: Some(match fact.status() {
            Status::Completed { usage }
            | Status::Failed { usage, .. }
            | Status::Incomplete { usage, .. }
            | Status::Cancelled { usage } => usage.is_some(),
            Status::Pending | Status::Unknown => false,
        }),
    }
}

#[cfg(test)]
mod source1_tests {
    use super::*;
    use runne_application::provider::ProviderUnknownTerminalFact;

    #[test]
    fn source1_missing_usage_keeps_factual_completion_and_unknown_accounting() {
        let effect = project_unknown_source1_effect(
            &ProviderUnknownTerminalFact {
                disposition: runne_provider::ProviderTerminalDisposition::Completed,
                usage: None,
                output_digest: Some([7; 32]),
                output_was_published: false,
                output_was_applied: false,
            },
            true,
        );
        assert_eq!(effect.outcome, RemoteOutcome::Completed);
        assert_eq!(effect.accounting, runne_api::RemoteAccountingV1::Unknown);
        assert_eq!(effect.publication, runne_api::RemotePublicationV1::Withheld);
        assert_eq!(effect.cancellation, RemoteCancel::Unconfirmed);
        assert_eq!(effect.usage_known, Some(false));
    }

    #[test]
    fn source1_exact_usage_stays_known_when_accounting_is_unknown() {
        let usage = runne_provider::ProviderUsage::new(3, 4, 1, 2).unwrap();
        let effect = project_unknown_source1_effect(
            &ProviderUnknownTerminalFact {
                disposition: runne_provider::ProviderTerminalDisposition::RemoteFailed,
                usage: Some(usage),
                output_digest: None,
                output_was_published: false,
                output_was_applied: false,
            },
            false,
        );
        assert_eq!(effect.outcome, RemoteOutcome::Failed);
        assert_eq!(effect.accounting, runne_api::RemoteAccountingV1::Unknown);
        assert_eq!(effect.usage_known, Some(true));
    }
}
