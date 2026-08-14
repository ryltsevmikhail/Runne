use std::path::{Path, PathBuf};

use base64::{
    Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::URL_SAFE_NO_PAD,
};
use gocode_daemon::config::ConfigurationSnapshot;
use hmac::{Hmac, Mac};
use reqwest::Client;
use serde_json::Value;
use sha2::Sha256;

pub mod owner_private;

pub struct TestSession {
    pub client: Client,
    pub authorization: String,
}

// Each integration target compiles this shared support module independently.
#[allow(dead_code)]
pub async fn seed_project_workspace(
    client: &Client,
    address: std::net::SocketAddr,
    authorization: &str,
    project_id: &str,
    workspace_id: &str,
) {
    let project = client
        .post(format!("https://{address}/v1/projects"))
        .header("authorization", authorization)
        .header("x-command-id", "018f2e3a-7000-7000-8000-0000000000f1")
        .header("idempotency-key", "canonical-project-create")
        .json(&serde_json::json!({
            "projectId": project_id,
            "displayName": "Project",
        }))
        .send()
        .await
        .expect("create canonical project");
    assert_eq!(project.status(), reqwest::StatusCode::ACCEPTED);
    let workspace = client
        .post(format!(
            "https://{address}/v1/projects/{project_id}/workspaces"
        ))
        .header("authorization", authorization)
        .header("x-command-id", "018f2e3a-7000-7000-8000-0000000000f2")
        .header("idempotency-key", "canonical-workspace-create")
        .json(&serde_json::json!({
            "workspaceId": workspace_id,
            "displayName": "Workspace",
        }))
        .send()
        .await
        .expect("create canonical workspace");
    assert_eq!(workspace.status(), reqwest::StatusCode::ACCEPTED);
}

pub async fn connect_session(config: &ConfigurationSnapshot) -> TestSession {
    let profile_path =
        PathBuf::from(&config.replay_integrity_key_path).with_file_name("client-profile.json");
    let profile: Value =
        serde_json::from_slice(&std::fs::read(profile_path).expect("read client profile"))
            .expect("parse client profile");
    let certificate = STANDARD
        .decode(
            profile["certificateDerBase64"]
                .as_str()
                .expect("certificate DER"),
        )
        .expect("decode certificate DER");
    let client = Client::builder()
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .add_root_certificate(
            reqwest::Certificate::from_der(&certificate).expect("profile certificate"),
        )
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("pinned test client");
    let endpoint = profile["endpoint"].as_str().expect("profile endpoint");
    let client_nonce = [8; 32];
    let not_before = chrono::Utc::now();
    let expiry = not_before + chrono::TimeDelta::seconds(30);
    let not_before = not_before.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let expiry = expiry.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let secret_path = Path::new(
        profile["bootstrapSecretPath"]
            .as_str()
            .expect("bootstrap secret path"),
    );
    let secret = std::fs::read(secret_path).expect("read bootstrap secret");
    let mut preallocation_mac = Hmac::<Sha256>::new_from_slice(&secret).expect("HMAC key");
    preallocation_mac.update(&proof_transcript(
        &profile,
        b"/v1/local-session/challenges",
        &not_before,
        &expiry,
        &client_nonce,
        None,
    ));
    let challenge = client
        .post(format!("{endpoint}/v1/local-session/challenges"))
        .json(&serde_json::json!({
            "wireVersion": "3",
            "keyVersion": 1,
            "clientNonce": URL_SAFE_NO_PAD.encode(client_nonce),
            "notBefore": not_before,
            "expiry": expiry,
            "preallocationProof": URL_SAFE_NO_PAD.encode(preallocation_mac.finalize().into_bytes()),
        }))
        .send()
        .await
        .expect("challenge request");
    assert_eq!(challenge.status(), reqwest::StatusCode::OK);
    let challenge: Value = challenge.json().await.expect("challenge response");
    assert_eq!(challenge["wireVersion"], "3");
    assert_eq!(challenge["keyVersion"], 1);
    let server_nonce: [u8; 32] = URL_SAFE_NO_PAD
        .decode(challenge["serverNonce"].as_str().expect("server nonce"))
        .expect("decode server nonce")
        .try_into()
        .expect("32-byte server nonce");
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("HMAC key");
    mac.update(&proof_transcript(
        &profile,
        b"/v1/local-session/authenticate",
        &not_before,
        &expiry,
        &client_nonce,
        Some(server_nonce),
    ));
    let authority = [10; 32];
    let authenticated = client
        .post(format!("{endpoint}/v1/local-session/authenticate"))
        .json(&serde_json::json!({
            "wireVersion": "3",
            "keyVersion": 1,
            "challengeId": challenge["challengeId"],
            "finalProof": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
            "authority": URL_SAFE_NO_PAD.encode(authority),
        }))
        .send()
        .await
        .expect("authenticate request");
    assert_eq!(authenticated.status(), reqwest::StatusCode::OK);
    TestSession {
        client,
        authorization: format!("GocodeSession {}", URL_SAFE_NO_PAD.encode(authority)),
    }
}

fn proof_transcript(
    profile: &Value,
    endpoint: &[u8],
    not_before: &str,
    expiry: &str,
    client_nonce: &[u8; 32],
    server_nonce: Option<[u8; 32]>,
) -> Vec<u8> {
    let authority = decode_hex::<16>(&profile["launchAuthorityId"]);
    let schema = decode_hex::<32>(&profile["schemaHash"]);
    let executable = decode_hex::<32>(&profile["executableSha256"]);
    let lineage = uuid::Uuid::parse_str(profile["eventLogLineageId"].as_str().unwrap()).unwrap();
    let instance = uuid::Uuid::parse_str(profile["daemonInstanceId"].as_str().unwrap()).unwrap();
    let session = decode_hex::<16>(&profile["sessionId"]);
    let generation = profile["launchGeneration"].as_u64().unwrap().to_be_bytes();
    let fields: [&[u8]; 16] = [
        b"gocode-local-session-v3",
        &authority,
        profile["principalId"].as_str().unwrap().as_bytes(),
        lineage.as_bytes(),
        profile["profileId"].as_str().unwrap().as_bytes(),
        &schema,
        &executable,
        instance.as_bytes(),
        &generation,
        &session,
        endpoint,
        b"POST",
        not_before.as_bytes(),
        expiry.as_bytes(),
        client_nonce,
        &[],
    ];
    let input = gocode_pairing_crypto::BootstrapTranscriptV3 {
        key_version: 1,
        fields,
    };
    server_nonce.map_or_else(
        || gocode_pairing_crypto::encode_preallocation_transcript(&input).unwrap(),
        |nonce| gocode_pairing_crypto::encode_final_transcript(&input, nonce).unwrap(),
    )
}

fn decode_hex<const N: usize>(value: &Value) -> [u8; N] {
    let mut output = [0; N];
    hex::decode_to_slice(value.as_str().expect("hex string"), &mut output).expect("decode hex");
    output
}
