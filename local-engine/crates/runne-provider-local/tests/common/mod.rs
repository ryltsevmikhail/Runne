//! Shared fixtures for provider-local integration tests: one admitted
//! GGUF model in a real store, adapters wired over explicit test ports.
//! Each test binary compiles this module separately; unused helpers
//! are expected.
#![allow(dead_code)]

use runne_local_model::gguf_limits::GGUF_MAGIC;
use runne_model_store::{LicenseAcceptance, ModelArtifactStore};
use runne_provider_local::adapter::{
    LocalExecutionPermitPort, LocalProviderAdapter, LocalUsageSettlementPort,
};
use runne_provider_local::port::{DispatchRequest, ProviderCall};
use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::Path;

pub struct AllowPermit;

impl LocalExecutionPermitPort for AllowPermit {
    fn resolve_consumed(
        &self,
        _attempt_id: &[u8; 16],
    ) -> Result<bool, runne_provider_local::ProviderError> {
        Ok(true)
    }
}

/// Compiled into every test binary via `mod common`; not every binary
/// exercises the denial path.
#[allow(dead_code)]
pub struct DenyPermit;

impl LocalExecutionPermitPort for DenyPermit {
    fn resolve_consumed(
        &self,
        _attempt_id: &[u8; 16],
    ) -> Result<bool, runne_provider_local::ProviderError> {
        Ok(false)
    }
}

#[derive(Default)]
pub struct SettlementPort {
    pub settled: std::collections::BTreeSet<[u8; 16]>,
}

impl LocalUsageSettlementPort for SettlementPort {
    fn settle_once(&mut self, attempt_id: &[u8; 16], _in_tok: u64, _out_tok: u64) {
        self.settled.insert(*attempt_id);
    }
}

/// 24-byte minimal GGUF: magic, version 3, zero tensors, zero kv pairs.
pub fn gguf_image() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&GGUF_MAGIC);
    out.extend_from_slice(&3u32.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());
    out
}

pub fn hex_digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(data))
}

pub fn sha(data: &[u8]) -> String {
    format!("sha256:{}", hex_digest(data))
}

pub struct Fixture {
    /// Catalog digest form (bare hex) the adapter keys known manifests by.
    pub manifest_digest: String,
    /// Full artifact digest (`sha256:...`) bound to the admitted permit.
    pub artifact_digest: String,
}

/// Admits the test model into a real store rooted at `dir` and returns
/// both digest forms. The blob lands at `dir/blobs/<hex>`, which is the
/// only path the adapter may open artifacts from.
pub fn admit_model(dir: &Path) -> Fixture {
    let mut store = ModelArtifactStore::open(dir).expect("store");
    let image = gguf_image();
    let artifact_digest = sha(&image);
    let manifest = format!(
        "{{\"artifacts\":[{{\"byteLength\":24,\"contentType\":\"application/gguf\",\"digest\":\"{artifact_digest}\",\"role\":\"model\"}}],\"capabilities\":{{\"contextMaxTokens\":4096,\"modalities\":[\"text\"],\"outputMaxTokens\":1024,\"reasoning\":false,\"streaming\":true,\"structuredOutput\":false,\"tools\":false}},\"chatTemplate\":{{\"id\":\"c\",\"revision\":\"1\",\"sourceDigest\":\"sha256:{}\"}},\"compatibility\":{{\"backendProfiles\":[{{\"id\":\"llama-cpp-cpu-macos-arm64-v1\",\"revision\":\"v1\"}}]}},\"format\":\"GGUF\",\"hardwareRequirements\":{{\"arch\":\"arm64\",\"minRamBytes\":1,\"os\":\"macos\"}},\"license\":\"Apache-2.0\",\"manifestDigest\":\"__MDG__\",\"minCompatibleRuntime\":\"0.1.0\",\"modelID\":\"m1\",\"modelRevision\":\"r1\",\"provenance\":{{\"acquiredAt\":\"2026-09-04T00:00:00Z\",\"publisher\":\"p\",\"sourceDigest\":\"sha256:{}\",\"sourceUri\":\"https://x\"}},\"schemaVersion\":\"ModelManifestV1\",\"tokenizer\":{{\"configDigest\":\"sha256:{}\",\"family\":\"bpe\",\"revision\":\"1\"}},\"toolProtocol\":{{\"id\":\"tp\",\"revision\":\"1\",\"schemaDigest\":\"sha256:{}\",\"semantics\":\"s\"}}}}",
        hex_digest(b"c"),
        hex_digest(b"s"),
        hex_digest(b"t"),
        hex_digest(b"tp")
    );
    let preimage = manifest.replace("\"manifestDigest\":\"__MDG__\",", "");
    let manifest_digest = hex_digest(preimage.as_bytes());
    let manifest = manifest.replace("__MDG__", &format!("sha256:{manifest_digest}"));
    let candidate = store
        .stage_import(manifest.as_bytes(), &mut Cursor::new(image))
        .expect("stage");
    let accepted = LicenseAcceptance {
        license_digest: hex_digest(candidate.license.as_bytes()),
    };
    store
        .admit(&candidate.candidate_id, &accepted)
        .expect("admit");
    Fixture {
        manifest_digest,
        artifact_digest,
    }
}

/// Builds an adapter over the store at `dir` with the given ports.
pub fn adapter<P, S>(
    dir: &Path,
    permit: P,
    settlement: S,
    fixture: &Fixture,
) -> LocalProviderAdapter<P, S>
where
    P: LocalExecutionPermitPort + Send + Sync,
    S: LocalUsageSettlementPort + Send + Sync,
{
    let known: BTreeMap<String, String> = [(fixture.manifest_digest.clone(), "m1".into())].into();
    LocalProviderAdapter::new(permit, settlement, known, dir.join("blobs"))
}

pub fn call(manifest_digest: &str, text: &str) -> ProviderCall {
    ProviderCall {
        call_id: [5; 16],
        model_ref: "local:m1".into(),
        manifest_digest: manifest_digest.into(),
        max_output_tokens: 256,
        inputs: vec![("user".into(), text.into())],
        required_capabilities: vec!["streaming".into()],
        extension: serde_json::Value::Null,
    }
}

pub fn dispatch_request(call_id: &[u8; 16], artifact_digest: &str) -> DispatchRequest {
    DispatchRequest {
        attempt_id: [2; 16],
        generation_id: [3; 16],
        stream_id: [4; 16],
        prepared_call_id: *call_id,
        artifact_digest: artifact_digest.to_string(),
    }
}
