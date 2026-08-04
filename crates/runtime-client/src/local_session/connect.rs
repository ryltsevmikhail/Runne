
fn session_peer_from_ready(
    ready: &ProtectedReadyV1,
    request: &ProtectedLaunchRequestV1,
    keys: &ProtectedActivationKeys,
) -> Result<SessionPeer, LaunchAuthorityError> {
    ready.verify_exact(request, keys)?;
    let expected_schema_hash: [u8; 32] = hex::decode(GOLDEN_BUNDLE_HASH)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(LaunchAuthorityError::ProfileHashMismatch)?;
    let profile = ready.profile();
    let stable = ready.stable();
    if profile.transport_profile_id() != PROTECTED_BUNDLED_TRANSPORT_PROFILE_ID {
        return Err(LaunchAuthorityError::DowngradedExternalProfile);
    }
    if profile.runtime_profile_schema_version() != PROTECTED_RUNTIME_PROFILE_SCHEMA_VERSION
        || profile.profile_id() != crate::EXPECTED_BUNDLE_ID
        || profile.profile_hash() != &expected_schema_hash
        || stable.principal_id() != request.principal_id()
        || stable.profile_id() != profile.profile_id()
        || stable.profile_hash() != profile.profile_hash()
        || stable.capability_digest() != profile.capability_digest()
        || !ready
            .capabilities()
            .iter()
            .map(String::as_str)
            .eq(crate::REQUIRED_RUNTIME_CAPABILITIES.iter().copied())
        || ordered_capability_digest(ready.capabilities()) != *profile.capability_digest()
    {
        return Err(LaunchAuthorityError::ProfileHashMismatch);
    }
    let certificate_digest: [u8; 32] = Sha256::digest(ready.certificate_der()).into();
    if &certificate_digest != ready.certificate_sha256() {
        return Err(LaunchAuthorityError::ReadinessProofMismatch);
    }
    let (endpoint, origin) =
        parse_endpoint(ready.endpoint()).map_err(|_| LaunchAuthorityError::InvalidContract)?;
    Ok(SessionPeer {
        endpoint,
        origin,
        certificate_der: ready.certificate_der().to_vec(),
        certificate_sha256: *ready.certificate_sha256(),
        authority_id: *stable.authority_id(),
        principal_id: stable.principal_id().to_owned(),
        event_log_lineage_id: uuid::Uuid::from_bytes(*stable.lineage_id()),
        daemon_instance_id: uuid::Uuid::from_bytes(*ready.daemon_instance_id()),
        launch_generation: ready.launch_generation(),
        expected_session_id: Some(*ready.session_id()),
        schema_hash: *profile.profile_hash(),
        capabilities: ready.capabilities().to_vec(),
        capability_digest: *profile.capability_digest(),
    })
}

pub async fn connect(
    profile: LocalRuntimeProfile,
    timeout: Duration,
) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
    let LocalRuntimeProfile {
        endpoint,
        origin,
        certificate_der,
        certificate_sha256,
        bootstrap_secret_path,
        authority_id,
        principal_id,
        event_log_lineage_id,
        daemon_instance_id,
        launch_generation,
        schema_hash,
        capabilities,
        capability_digest,
    } = profile;
    connect_with_peer(
        SessionPeer {
            endpoint,
            origin,
            certificate_der,
            certificate_sha256,
            authority_id,
            principal_id,
            event_log_lineage_id,
            daemon_instance_id,
            launch_generation,
            expected_session_id: None,
            schema_hash,
            capabilities,
            capability_digest,
        },
        BootstrapMaterial::ExternalPath(bootstrap_secret_path),
        RuntimeTransportKind::ExternalLocal,
        timeout,
    )
    .await
}

async fn connect_with_peer(
    profile: SessionPeer,
    bootstrap_material: BootstrapMaterial,
    transport_kind: RuntimeTransportKind,
    timeout: Duration,
) -> Result<AuthenticatedRuntimeClient, LocalRuntimeConnectError> {
    if timeout.is_zero() || timeout > MAXIMUM_TIMEOUT {
        return Err(RuntimeTransportError::InvalidTimeout.into());
    }
    let certificate =
        reqwest::Certificate::from_der(&profile.certificate_der).map_err(|_| incompatible())?;
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(certificate)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| RuntimeTransportError::Unavailable)?;

    let mut client_nonce = [0; 32];
    let mut requested_server_nonce = [0; 32];
    OsRng.fill_bytes(&mut client_nonce);
    OsRng.fill_bytes(&mut requested_server_nonce);
    let challenge_body = serde_json::to_vec(&ChallengeRequest {
        client_nonce: URL_SAFE_NO_PAD.encode(client_nonce),
        server_nonce: URL_SAFE_NO_PAD.encode(requested_server_nonce),
    })
    .map_err(|_| incompatible())?;
    let challenge_response = client
        .post(format!("{}/v1/local-session/challenges", profile.origin))
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(challenge_body)
        .send()
        .await
        .map_err(|_| RuntimeTransportError::PeerIdentityMismatch)?;
    let challenge: ChallengeResponse = read_json(challenge_response).await?;
    let challenge_id = decode_16(&challenge.challenge_id)?;
    let server_nonce = decode_32(&challenge.server_nonce)?;
    if server_nonce != requested_server_nonce || challenge_id != server_nonce[..16] {
        return Err(incompatible());
    }

    // The bootstrap secret is deliberately opened only after a pinned TLS
    // response has authenticated the peer that issued this challenge.
    let bootstrap_secret = match bootstrap_material {
        BootstrapMaterial::ExternalPath(path) => Zeroizing::new(read_bootstrap_secret(&path)?),
        BootstrapMaterial::Protected(secret) => secret,
    };
    let transcript = Zeroizing::new(proof_transcript(&profile, server_nonce, client_nonce));
    let mut mac =
        Hmac::<Sha256>::new_from_slice(bootstrap_secret.as_ref()).map_err(|_| incompatible())?;
    mac.update(&transcript);
    let proof = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut authority = Zeroizing::new([0; 32]);
    while *authority == [0; 32] {
        OsRng.fill_bytes(authority.as_mut());
    }
    let authenticate_body = serde_json::to_vec(&AuthenticateRequest {
        challenge_id: URL_SAFE_NO_PAD.encode(challenge_id),
        proof: URL_SAFE_NO_PAD.encode(proof.as_ref()),
        authority: URL_SAFE_NO_PAD.encode(authority.as_ref()),
    })
    .map_err(|_| incompatible())?;
    let authenticate_response = client
        .post(format!("{}/v1/local-session/authenticate", profile.origin))
        .header(ACCEPT, "application/json")
        .header(CONTENT_TYPE, "application/json")
        .body(authenticate_body)
        .send()
        .await
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    let authenticated: AuthenticateResponse = read_json(authenticate_response).await?;
    let issued_session_id = decode_lower_hex_16(&authenticated.session_id)?;
    if authenticated.expires_at_monotonic_millis == 0 || issued_session_id == [0; 16] {
        return Err(incompatible());
    }

    let credential = RuntimeCredential::from_local_session(*authority);
    let profile_response = client
        .get(format!("{}/v1/runtime/profile", profile.origin))
        .header(ACCEPT, "application/json")
        .header(AUTHORIZATION, credential.authorization_header()?)
        .send()
        .await
        .map_err(|_| RuntimeTransportError::Unavailable)?;
    let remote: SessionRuntimeProfileWire = read_json(profile_response).await?;
    let session = verify_remote_profile(&profile, remote, issued_session_id)?;
    Ok(match transport_kind {
        RuntimeTransportKind::ExternalLocal => AuthenticatedRuntimeClient::from_local_session(
            client,
            profile.origin,
            credential,
            session,
        ),
        RuntimeTransportKind::ProtectedBundled => {
            AuthenticatedRuntimeClient::from_protected_bundled_session(
                client,
                profile.origin,
                credential,
                session,
            )
        }
    })
}
