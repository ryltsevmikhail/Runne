//! Shared fixture for `LocalRuntimeProfile` integration tests. Included by
//! several test targets, which use different subsets of the helpers.

#![allow(dead_code)]

use std::fs;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use runne_runtime_client::{EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH, REQUIRED_RUNTIME_CAPABILITIES};
use sha2::{Digest, Sha256};

pub fn certificate_der() -> Vec<u8> {
    let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
    parameters.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::V4(
        std::net::Ipv4Addr::LOCALHOST,
    ))];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    parameters
        .self_signed(&key)
        .expect("certificate")
        .der()
        .to_vec()
}

pub fn ordered_capability_digest(capabilities: &[&str]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"gocode/local-runtime/capability-digest/v1\0");
    hasher.update(u32::try_from(capabilities.len()).unwrap().to_be_bytes());
    for capability in capabilities {
        hasher.update(u32::try_from(capability.len()).unwrap().to_be_bytes());
        hasher.update(capability.as_bytes());
    }
    hasher.finalize().into()
}

#[cfg(unix)]
pub fn secure(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure file");
}

#[cfg(not(unix))]
pub const fn secure(_: &std::path::Path) {}

/// Writes a valid schemaVersion 3 profile pinned to the required capability
/// profile, with a consistent capability digest and 0600 permissions.
pub fn write_profile(directory: &std::path::Path, endpoint: &str) -> std::path::PathBuf {
    let bootstrap_path = directory.join("bootstrap.secret");
    fs::write(&bootstrap_path, [0x7b; 32]).expect("write bootstrap secret");
    secure(&bootstrap_path);
    let certificate = certificate_der();
    let profile_path = directory.join("client-profile.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 3,
            "transportProfileId": "gocode-local-runtime/2",
            "profileId": EXPECTED_BUNDLE_ID,
            "schemaHash": GOLDEN_BUNDLE_HASH,
            "capabilities": REQUIRED_RUNTIME_CAPABILITIES,
            "capabilityDigest": hex::encode(ordered_capability_digest(REQUIRED_RUNTIME_CAPABILITIES)),
            "endpoint": endpoint,
            "certificateDerBase64": STANDARD.encode(&certificate),
            "certificateSha256": hex::encode(Sha256::digest(&certificate)),
            "executableSha256": "0e".repeat(32),
            "bootstrapSecretPath": bootstrap_path,
            "authorityId": "018f2e3a700070008000000000000001",
            "launchAuthorityId": "018f2e3a700070008000000000000006",
            "principalId": "local-owner",
            "eventLogLineageId": "018f2e3a-7000-7000-8000-000000000003",
            "daemonInstanceId": "018f2e3a-7000-7000-8000-000000000002",
            "launchGeneration": 7,
            "sessionId": "018f2e3a700070008000000000000005"
        }))
        .expect("profile JSON"),
    )
    .expect("write profile");
    secure(&profile_path);
    profile_path
}

/// Applies `mutate` to the stored profile JSON and restores 0600 permissions.
pub fn rewrite_profile(
    profile_path: &std::path::Path,
    mutate: impl FnOnce(&mut serde_json::Value),
) {
    let mut profile: serde_json::Value =
        serde_json::from_slice(&fs::read(profile_path).expect("read profile"))
            .expect("parse profile");
    mutate(&mut profile);
    fs::write(
        profile_path,
        serde_json::to_vec(&profile).expect("profile JSON"),
    )
    .expect("rewrite profile");
    secure(profile_path);
}
