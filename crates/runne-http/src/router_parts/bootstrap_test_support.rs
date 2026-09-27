fn session_service(binding: runne_api::RuntimeSessionBinding) -> Arc<Mutex<LocalSessionService>> {
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let store =
        Arc::new(runne_store::local_session::SqliteBootstrapReservationStore::new(connection));
    Arc::new(Mutex::new(LocalSessionService::with_reservation_store(
        binding.clone(),
        *binding.stable().authority_id(),
        [0x0e; 32],
        [7; 32],
        store,
    )))
}

struct TestEnrollmentGenerationStore(std::sync::atomic::AtomicU64);

impl TestEnrollmentGenerationStore {
    fn at_generation(generation: u64) -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicU64::new(generation)))
    }
}

impl runne_application::local_session::EnrollmentLaunchGenerationStore
    for TestEnrollmentGenerationStore
{
    fn consume_reserved_enrollment_generation(
        &self,
        generation: u64,
    ) -> Result<(), runne_application::local_session::EnrollmentLaunchGenerationConsumeError> {
        use runne_application::local_session::EnrollmentLaunchGenerationConsumeError as Error;
        let current = self.0.load(std::sync::atomic::Ordering::Acquire);
        if current.checked_add(1) != Some(generation) {
            return Err(Error::Rejected);
        }
        self.0
            .compare_exchange(
                current,
                generation,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| Error::Rejected)
    }

    fn reserve_next_enrollment_generation(
        &self,
    ) -> Result<u64, runne_application::local_session::EnrollmentLaunchGenerationConsumeError> {
        self.0
            .load(std::sync::atomic::Ordering::Acquire)
            .checked_add(1)
            .ok_or(runne_application::local_session::EnrollmentLaunchGenerationConsumeError::Unavailable)
    }
}

fn protected_session_service(
    binding: runne_api::RuntimeSessionBinding,
    generation_store: Arc<TestEnrollmentGenerationStore>,
) -> Arc<Mutex<LocalSessionService>> {
    let connection =
        open_managed_connection(std::path::Path::new(":memory:"), ConnectionMode::Writer).unwrap();
    apply_migrations(&connection).unwrap();
    let reservation_store =
        Arc::new(runne_store::local_session::SqliteBootstrapReservationStore::new(connection));
    Arc::new(Mutex::new(
        LocalSessionService::new_protected_with_stores(
            binding.clone(),
            *binding.stable().authority_id(),
            [0x0e; 32],
            [7; 32],
            reservation_store,
            generation_store,
            Duration::ZERO,
            Duration::from_secs(30),
        )
        .unwrap(),
    ))
}

async fn bootstrap_authority(app: &Router, binding: &runne_api::RuntimeSessionBinding) -> [u8; 32] {
    bootstrap_authority_with(app, binding, [7; 32], [10; 32]).await
}

async fn bootstrap_authority_with(
    app: &Router,
    binding: &runne_api::RuntimeSessionBinding,
    bootstrap_secret: [u8; 32],
    authority: [u8; 32],
) -> [u8; 32] {
    let client_nonce = [9; 32];
    let not_before = chrono::Utc::now();
    let expiry = not_before + chrono::TimeDelta::seconds(30);
    let not_before = not_before.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let expiry = expiry.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let preallocation = v3_transcript(
        binding,
        runne_application::local_session::BOOTSTRAP_PREALLOCATION_ENDPOINT_V3,
        &not_before,
        &expiry,
        &client_nonce,
        None,
    );
    let challenge = app
        .clone()
        .oneshot(json_request(
            "/v1/local-session/challenges",
            serde_json::json!({
                "wireVersion":"3", "keyVersion":1,
                "clientNonce":URL_SAFE_NO_PAD.encode(client_nonce),
                "notBefore":not_before, "expiry":expiry,
                "preallocationProof":v3_proof(&preallocation, &bootstrap_secret),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(challenge.status(), StatusCode::OK);
    let challenge: serde_json::Value =
        serde_json::from_slice(&to_bytes(challenge.into_body(), 8192).await.unwrap()).unwrap();
    let server_nonce: [u8; 32] = URL_SAFE_NO_PAD
        .decode(challenge["serverNonce"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let final_transcript = v3_transcript(
        binding,
        runne_application::local_session::BOOTSTRAP_FINAL_ENDPOINT_V3,
        &not_before,
        &expiry,
        &client_nonce,
        Some(server_nonce),
    );
    let authenticated = app
        .clone()
        .oneshot(json_request(
            "/v1/local-session/authenticate",
            serde_json::json!({
                "wireVersion":"3", "keyVersion":1,
                "challengeId":challenge["challengeId"],
                "finalProof":v3_proof(&final_transcript, &bootstrap_secret),
                "authority":URL_SAFE_NO_PAD.encode(authority),
            }),
        ))
        .await
        .unwrap();
    assert_eq!(authenticated.status(), StatusCode::OK);
    authority
}

fn v3_transcript(
    binding: &runne_api::RuntimeSessionBinding,
    endpoint: &[u8],
    not_before: &str,
    expiry: &str,
    client_nonce: &[u8; 32],
    server_nonce: Option<[u8; 32]>,
) -> Vec<u8> {
    let stable = binding.stable();
    let instance = binding.ephemeral().daemon_instance_id().into_bytes();
    let generation = binding.ephemeral().launch_generation().to_be_bytes();
    let fields: [&[u8]; 16] = [
        runne_application::local_session::BOOTSTRAP_PROTOCOL_V3,
        stable.authority_id(),
        stable.principal_id().as_str().as_bytes(),
        stable.lineage_id().as_bytes(),
        stable.profile_id().as_bytes(),
        stable.schema_hash(),
        &[0x0e; 32],
        &instance,
        &generation,
        binding.ephemeral().session_id(),
        endpoint,
        runne_application::local_session::BOOTSTRAP_HTTP_METHOD_V3,
        not_before.as_bytes(),
        expiry.as_bytes(),
        client_nonce,
        &[],
    ];
    let input = runne_pairing_crypto::BootstrapTranscriptV3 {
        key_version: 1,
        fields,
    };
    server_nonce.map_or_else(
        || runne_pairing_crypto::encode_preallocation_transcript(&input).unwrap(),
        |nonce| runne_pairing_crypto::encode_final_transcript(&input, nonce).unwrap(),
    )
}

fn v3_proof(transcript: &[u8], bootstrap_secret: &[u8; 32]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(bootstrap_secret).unwrap();
    mac.update(transcript);
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

fn json_request(uri: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}
