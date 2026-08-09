use chrono::{SecondsFormat, TimeDelta, Utc};
use gocode_pairing_crypto::{
    BootstrapTranscriptV3, encode_final_transcript, encode_preallocation_transcript,
};
use serde::{Deserialize, Serialize};

use crate::LocalRuntimeConnectError;

const WIRE_VERSION: &str = "3";
const KEY_VERSION: u16 = 1;
const PROTOCOL: &[u8] = b"gocode-local-session-v3";
const PREALLOCATION_ENDPOINT: &[u8] = b"/v1/local-session/challenges";
const FINAL_ENDPOINT: &[u8] = b"/v1/local-session/authenticate";
const METHOD: &[u8] = b"POST";

pub(super) struct BootstrapWindow {
    pub client_nonce: [u8; 32],
    pub not_before: String,
    pub expiry: String,
}

impl BootstrapWindow {
    pub fn new(client_nonce: [u8; 32]) -> Result<Self, LocalRuntimeConnectError> {
        let not_before = Utc::now();
        let expiry = not_before
            .checked_add_signed(TimeDelta::seconds(30))
            .ok_or_else(super::incompatible)?;
        Ok(Self {
            client_nonce,
            not_before: not_before.to_rfc3339_opts(SecondsFormat::Micros, true),
            expiry: expiry.to_rfc3339_opts(SecondsFormat::Micros, true),
        })
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChallengeRequest {
    pub wire_version: &'static str,
    pub key_version: u16,
    pub client_nonce: String,
    pub not_before: String,
    pub expiry: String,
    pub preallocation_proof: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ChallengeResponse {
    pub wire_version: String,
    pub key_version: u16,
    pub challenge_id: String,
    pub server_nonce: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct AuthenticateRequest {
    pub wire_version: &'static str,
    pub key_version: u16,
    pub challenge_id: String,
    pub final_proof: String,
    pub authority: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct AuthenticateResponse {
    pub wire_version: String,
    pub key_version: u16,
    pub expires_at_monotonic_millis: u64,
    pub session_id: String,
}

pub(super) fn preallocation_transcript(
    peer: &super::SessionPeer,
    window: &BootstrapWindow,
) -> Result<Vec<u8>, LocalRuntimeConnectError> {
    encode(peer, window, PREALLOCATION_ENDPOINT, None)
}

pub(super) fn final_transcript(
    peer: &super::SessionPeer,
    window: &BootstrapWindow,
    server_nonce: [u8; 32],
) -> Result<Vec<u8>, LocalRuntimeConnectError> {
    encode(peer, window, FINAL_ENDPOINT, Some(server_nonce))
}

fn encode(
    peer: &super::SessionPeer,
    window: &BootstrapWindow,
    endpoint: &[u8],
    server_nonce: Option<[u8; 32]>,
) -> Result<Vec<u8>, LocalRuntimeConnectError> {
    let generation = peer.launch_generation.to_be_bytes();
    let session = peer.expected_session_id.ok_or_else(super::incompatible)?;
    let fields: [&[u8]; 16] = [
        PROTOCOL,
        &peer.launch_authority_id,
        peer.principal_id.as_bytes(),
        peer.event_log_lineage_id.as_bytes(),
        crate::EXPECTED_BUNDLE_ID.as_bytes(),
        &peer.schema_hash,
        &peer.executable_sha256,
        peer.daemon_instance_id.as_bytes(),
        &generation,
        &session,
        endpoint,
        METHOD,
        window.not_before.as_bytes(),
        window.expiry.as_bytes(),
        &window.client_nonce,
        &[],
    ];
    let input = BootstrapTranscriptV3 {
        key_version: KEY_VERSION,
        fields,
    };
    server_nonce
        .map_or_else(
            || encode_preallocation_transcript(&input),
            |nonce| encode_final_transcript(&input, nonce),
        )
        .map_err(|_| super::incompatible())
}

pub(super) const fn wire_version() -> &'static str {
    WIRE_VERSION
}

pub(super) const fn key_version() -> u16 {
    KEY_VERSION
}
