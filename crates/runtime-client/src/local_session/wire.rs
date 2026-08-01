#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest {
    client_nonce: String,
    server_nonce: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeResponse {
    challenge_id: String,
    server_nonce: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthenticateRequest {
    challenge_id: String,
    proof: String,
    authority: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthenticateResponse {
    expires_at_monotonic_millis: u64,
    session_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SessionRuntimeProfileWire {
    profile_id: String,
    schema_hash: String,
    runtime_version: String,
    capabilities: Vec<String>,
    capability_digest: String,
    authority_id: String,
    principal_id: String,
    event_log_lineage_id: String,
    daemon_instance_id: String,
    launch_generation: u64,
    session_id: String,
    authorization_epoch: u64,
    sensitivity_ceiling: String,
    certificate_sha256: String,
}
