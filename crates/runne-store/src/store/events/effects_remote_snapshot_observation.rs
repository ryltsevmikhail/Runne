fn project_nonterminal_remote(
    observation: Option<runne_application::provider::ProviderRemoteObservationProjection>,
    cancellation_requested: bool,
) -> runne_api::RemoteEffectV1 {
    use runne_application::provider::ProviderRemoteObservationProjection as Observation;

    let outcome = if observation == Some(Observation::Pending) {
        runne_api::RemoteEffectOutcomeV1::Running
    } else {
        runne_api::RemoteEffectOutcomeV1::Unknown
    };
    let cancellation = if cancellation_requested {
        runne_api::RemoteCancellationV1::Unconfirmed
    } else {
        runne_api::RemoteCancellationV1::NotRequested
    };
    runne_api::RemoteEffectV1 {
        outcome,
        publication: runne_api::RemotePublicationV1::Unknown,
        accounting: runne_api::RemoteAccountingV1::Unknown,
        cancellation,
        availability: runne_api::RemoteEffectAvailabilityV1::Unknown,
        capabilities: runne_api::RemoteEffectCapabilitiesV1 {
            status_check: false,
            stream_resume: false,
            remote_cancel: false,
        },
        usage_known: None,
    }
}
