use super::*;

/// Creates the production sender with the fixed DeepSeek HTTPS client.
pub fn production_effect() -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
    let profile = profile().map_err(|_| DeepSeekEffectError)?;
    let policy = DeepSeekTransportPolicy::for_profile(&profile).map_err(|_| DeepSeekEffectError)?;
    let credential =
        client::NativeCredential::current_process().map_err(|_| DeepSeekEffectError)?;
    Ok(Arc::new(
        Sender::new(
            profile,
            credential,
            client::production_client(&policy).map_err(|_| DeepSeekEffectError)?,
        )
        .map_err(|_| DeepSeekEffectError)?,
    ))
}

/// Creates the fixture-only sender and an opaque request-authentication gate.
#[doc(hidden)]
pub fn effect_from_loopback_fixture(
    client: reqwest::Client,
) -> Result<(Arc<dyn DeepSeekEffect>, client::FixtureRequestAuthenticator), DeepSeekEffectError> {
    effect_from_loopback_fixture_inner(client, None)
}

/// Creates the fixture sender while retaining the production point-of-use
/// credential materializer boundary.
#[doc(hidden)]
pub fn effect_from_loopback_fixture_with_materializer(
    client: reqwest::Client,
    materializer: Arc<dyn runne_secure_store::ProviderCredentialDispatchMaterializer>,
) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError> {
    let profile = profile().map_err(|_| DeepSeekEffectError)?;
    let credential = client::NativeCredential::from_materializer(materializer);
    Ok(Arc::new(
        Sender::new(profile, credential, client).map_err(|_| DeepSeekEffectError)?,
    ))
}

/// Creates a loopback sender with a test-owned legacy-fixture credential hook.
#[doc(hidden)]
pub fn effect_from_loopback_fixture_with_legacy_credential_materializer<C>(
    client: reqwest::Client,
    credential: C,
) -> Result<Arc<dyn DeepSeekEffect>, DeepSeekEffectError>
where
    C: DeepSeekCredentialMaterializer + 'static,
{
    let profile = profile().map_err(|_| DeepSeekEffectError)?;
    Ok(Arc::new(
        Sender::new(profile, credential, client).map_err(|_| DeepSeekEffectError)?,
    ))
}

#[cfg(feature = "linux-native-enrollment-qualification")]
#[doc(hidden)]
pub fn effect_from_loopback_fixture_with_observer(
    client: reqwest::Client,
    observer: Arc<dyn DeepSeekEffectObserver>,
) -> Result<(Arc<dyn DeepSeekEffect>, client::FixtureRequestAuthenticator), DeepSeekEffectError> {
    effect_from_loopback_fixture_inner(client, Some(observer))
}

fn effect_from_loopback_fixture_inner(
    client: reqwest::Client,
    observer: Option<Arc<dyn diagnostics::DeepSeekEffectObserver>>,
) -> Result<(Arc<dyn DeepSeekEffect>, client::FixtureRequestAuthenticator), DeepSeekEffectError> {
    let credential = client::FixtureCredential::new();
    let authenticator = credential.request_authenticator();
    let effect = Arc::new(
        Sender::new_with_observer(
            profile().map_err(|_| DeepSeekEffectError)?,
            credential,
            client,
            observer,
        )
        .map_err(|_| DeepSeekEffectError)?,
    );
    Ok((effect, authenticator))
}

/// Builds the opaque fixture-only authorization gate before the loopback server starts.
#[doc(hidden)]
pub fn loopback_fixture_request_authenticator() -> FixtureRequestAuthenticator {
    client::FixtureCredential::new().request_authenticator()
}
