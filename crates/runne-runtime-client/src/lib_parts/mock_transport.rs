/// Constructs a loopback plaintext client for transport-bound integration
/// tests. This hook is unavailable in release builds.
///
/// # Errors
///
/// Returns an error unless `origin` is an exact loopback HTTP origin.
#[cfg(any(debug_assertions, feature = "test-support"))]
#[doc(hidden)]
pub fn mock_authenticated_runtime_client(
    origin: &str,
    session: RuntimeSessionInfo,
) -> Result<AuthenticatedRuntimeClient, RuntimeTransportError> {
    let (client, origin) = mock_loopback_transport(origin)?;
    Ok(AuthenticatedRuntimeClient::from_local_session(
        client,
        origin,
        RuntimeSessionAuthority::from_local_session([0x5a; 32]),
        session,
        Vec::new(),
    ))
}

/// Constructs a loopback plaintext client marked as protected-bundled for
/// native-host orchestration tests. This hook is unavailable in release
/// builds.
///
/// # Errors
///
/// Returns an error unless `origin` is an exact loopback HTTP origin.
#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub fn mock_protected_authenticated_runtime_client(
    origin: &str,
    session: RuntimeSessionInfo,
) -> Result<AuthenticatedRuntimeClient, RuntimeTransportError> {
    let (client, origin) = mock_loopback_transport(origin)?;
    Ok(AuthenticatedRuntimeClient::from_protected_bundled_session(
        client,
        origin,
        RuntimeSessionAuthority::from_local_session([0x5a; 32]),
        session,
        Vec::new(),
    ))
}

#[cfg(any(test, debug_assertions, feature = "test-support"))]
fn mock_loopback_transport(
    origin: &str,
) -> Result<(reqwest::Client, String), RuntimeTransportError> {
    let url =
        reqwest::Url::parse(origin).map_err(|_| RuntimeTransportError::EndpointNotLoopback)?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|host| host.is_loopback());
    if url.scheme() != "http"
        || !loopback
        || url.port().is_none()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(RuntimeTransportError::EndpointNotLoopback);
    }
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    Ok((client, origin.trim_end_matches('/').to_owned()))
}
