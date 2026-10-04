#[cfg(feature = "linux-native-enrollment-qualification")]
type DiagnosticSnapshot = Vec<runne_daemon_deepseek_effect::DeepSeekEffectDiagnostic>;
#[cfg(not(feature = "linux-native-enrollment-qualification"))]
type DiagnosticSnapshot = ();

async fn dispatch_on(
    server: DocumentedServer,
) -> (
    Captured,
    Result<Vec<runne_provider::ProviderStreamEvent>, DispatchError>,
    runne_daemon_deepseek_effect::FixtureRequestAuthenticator,
    DiagnosticSnapshot,
) {
    let profile = profile();
    let policy = DeepSeekTransportPolicy::for_profile(&profile).expect("exact policy");
    let client = loopback_fixture_client(&policy, server.address, &server.certificate_der)
        .expect("loopback client");
    #[cfg(feature = "linux-native-enrollment-qualification")]
    let observer = std::sync::Arc::new(RecordingObserver::default());
    #[cfg(feature = "linux-native-enrollment-qualification")]
    let (effect, authenticator) =
        runne_daemon_deepseek_effect::effect_from_loopback_fixture_with_observer(
            client,
            observer.clone(),
        )
        .expect("fixture effect");
    #[cfg(not(feature = "linux-native-enrollment-qualification"))]
    let (effect, authenticator) = effect_from_loopback_fixture(client).expect("fixture effect");
    let fixture = durable_dispatch(&profile, effect.as_ref());
    let ready = effect
        .stage_effect(fixture.request, fixture.credential)
        .await
        .expect("stage admitted effect");
    let dispatch = effect.dispatch_effect(ready, fixture.receipt).await;
    let events = match dispatch {
        Ok(stream) => {
            let mut events = Vec::new();
            let mut cursor = StreamCursor::new(0);
            loop {
                match ProviderPort::next(effect.as_ref(), &stream, cursor).await {
                    Ok(item) => {
                        events.push(item.event().clone());
                        cursor = StreamCursor::new(cursor.sequence() + 1);
                    }
                    Err(StreamError::Closed) => break,
                    Err(error) => panic!("unexpected stream error: {error}"),
                }
            }
            Ok(events)
        }
        Err(error) => Err(error),
    };
    #[cfg(feature = "linux-native-enrollment-qualification")]
    let diagnostics = observer.0.lock().expect("diagnostics lock").clone();
    #[cfg(not(feature = "linux-native-enrollment-qualification"))]
    let diagnostics = ();
    (
        server.task.await.expect("server task"),
        events,
        authenticator,
        diagnostics,
    )
}
