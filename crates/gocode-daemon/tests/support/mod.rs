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
    let server_nonce = [9; 32];
    let challenge = client
        .post(format!("{endpoint}/v1/local-session/challenges"))
        .json(&serde_json::json!({
            "clientNonce": URL_SAFE_NO_PAD.encode(client_nonce),
            "serverNonce": URL_SAFE_NO_PAD.encode(server_nonce),
        }))
        .send()
        .await
        .expect("challenge request");
    assert_eq!(challenge.status(), reqwest::StatusCode::OK);
    let challenge: Value = challenge.json().await.expect("challenge response");

    let secret_path = Path::new(
        profile["bootstrapSecretPath"]
            .as_str()
            .expect("bootstrap secret path"),
    );
    let secret = std::fs::read(secret_path).expect("read bootstrap secret");
    let mut mac = Hmac::<Sha256>::new_from_slice(&secret).expect("HMAC key");
    mac.update(&proof_transcript(&profile, server_nonce, client_nonce));
    let authority = [10; 32];
    let authenticated = client
        .post(format!("{endpoint}/v1/local-session/authenticate"))
        .json(&serde_json::json!({
            "challengeId": challenge["challengeId"],
            "proof": URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()),
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

fn proof_transcript(profile: &Value, server_nonce: [u8; 32], client_nonce: [u8; 32]) -> Vec<u8> {
    let mut output = b"gocode/local-runtime/bootstrap-proof/v2\0".to_vec();
    output.extend_from_slice(&2_u32.to_be_bytes());
    output.extend_from_slice(&decode_hex::<32>(&profile["certificateSha256"]));
    output.extend_from_slice(&server_nonce);
    output.extend_from_slice(&client_nonce);
    output.extend_from_slice(&decode_hex::<16>(&profile["authorityId"]));
    append_string(
        &mut output,
        profile["principalId"].as_str().expect("principal"),
    );
    output.extend_from_slice(
        uuid::Uuid::parse_str(profile["eventLogLineageId"].as_str().expect("lineage"))
            .expect("lineage UUID")
            .as_bytes(),
    );
    output.extend_from_slice(
        uuid::Uuid::parse_str(
            profile["daemonInstanceId"]
                .as_str()
                .expect("daemon instance"),
        )
        .expect("daemon instance UUID")
        .as_bytes(),
    );
    output.extend_from_slice(
        &profile["launchGeneration"]
            .as_u64()
            .expect("generation")
            .to_be_bytes(),
    );
    append_string(
        &mut output,
        profile["profileId"].as_str().expect("profile id"),
    );
    output.extend_from_slice(&decode_hex::<32>(&profile["schemaHash"]));
    output.extend_from_slice(&decode_hex::<32>(&profile["capabilityDigest"]));
    output
}

fn decode_hex<const N: usize>(value: &Value) -> [u8; N] {
    let mut output = [0; N];
    hex::decode_to_slice(value.as_str().expect("hex string"), &mut output).expect("decode hex");
    output
}

fn append_string(output: &mut Vec<u8>, value: &str) {
    output.extend_from_slice(
        &u16::try_from(value.len())
            .expect("bounded string")
            .to_be_bytes(),
    );
    output.extend_from_slice(value.as_bytes());
}
