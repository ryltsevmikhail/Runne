use std::fs;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::net::SocketAddr;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gocode_runtime_client::{
    EXPECTED_BUNDLE_ID, GOLDEN_BUNDLE_HASH, LocalProfileError, LocalRuntimeProfile,
    REQUIRED_RUNTIME_CAPABILITIES,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SanType};
use sha2::{Digest, Sha256};

fn write_profile(directory: &std::path::Path, endpoint: &str) -> std::path::PathBuf {
    let bootstrap_path = directory.join("bootstrap.secret");
    fs::write(&bootstrap_path, [0x7b; 32]).expect("write bootstrap secret");
    secure(&bootstrap_path);
    let certificate = certificate_der();
    let profile_path = directory.join("client-profile.json");
    fs::write(
        &profile_path,
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
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

fn rewrite_profile(profile_path: &std::path::Path, mutate: impl FnOnce(&mut serde_json::Value)) {
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

#[cfg(unix)]
#[test]
fn loads_profile_v2_without_reading_the_bootstrap_secret() {
    let directory = tempfile::tempdir().expect("temp directory");
    let endpoint = SocketAddr::from((Ipv4Addr::LOCALHOST, 43123));
    let profile_path = write_profile(directory.path(), &format!("https://{endpoint}"));
    fs::remove_file(directory.path().join("bootstrap.secret")).expect("remove secret");

    let profile = LocalRuntimeProfile::load(&profile_path).expect("load profile");

    assert_eq!(profile.endpoint().address(), endpoint);
    assert!(!format!("{profile:?}").contains("bootstrap"));
}

#[cfg(unix)]
#[test]
fn rejects_plaintext_external_and_unknown_profile_fields() {
    let directory = tempfile::tempdir().expect("temp directory");
    for endpoint in [
        "http://127.0.0.1:43123",
        "https://192.0.2.1:43123",
        "https://localhost:43123",
    ] {
        let profile_path = write_profile(directory.path(), endpoint);
        assert_eq!(
            LocalRuntimeProfile::load(&profile_path).expect_err("untrusted endpoint"),
            LocalProfileError::InvalidProfile
        );
    }

    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    rewrite_profile(&profile_path, |profile| {
        profile
            .as_object_mut()
            .expect("profile object")
            .insert("unexpected".to_owned(), serde_json::json!(true));
    });

    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("unknown field"),
        LocalProfileError::InvalidProfile
    );
}

#[cfg(unix)]
#[test]
fn rejects_profile_v1_and_wrong_certificate_digest_redacted() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = directory.path().join("client-profile.json");
    fs::write(
        &profile_path,
        br#"{"schemaVersion":1,"profileId":"gocode-ui-client/1","schemaHash":"redacted","endpoint":"http://127.0.0.1:1","tokenPath":"/tmp/legacy"}"#,
    )
    .expect("write v1");
    secure(&profile_path);
    let v1_error = LocalRuntimeProfile::load(&profile_path).expect_err("profile v1");
    assert_eq!(v1_error, LocalProfileError::InvalidProfile);
    assert_eq!(
        v1_error.to_string(),
        "local runtime profile is incompatible"
    );

    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    rewrite_profile(&profile_path, |profile| {
        profile["certificateSha256"] = serde_json::json!("00".repeat(32));
    });
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("wrong digest"),
        LocalProfileError::InvalidProfile
    );
}

#[cfg(unix)]
#[test]
fn rejects_missing_or_zero_executable_identity() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    rewrite_profile(&profile_path, |profile| {
        profile.as_object_mut().unwrap().remove("executableSha256");
    });
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("missing executable identity"),
        LocalProfileError::InvalidProfile
    );

    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    rewrite_profile(&profile_path, |profile| {
        profile["executableSha256"] = serde_json::json!("00".repeat(32));
    });
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("zero executable identity"),
        LocalProfileError::InvalidProfile
    );

    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    rewrite_profile(&profile_path, |profile| {
        profile.as_object_mut().unwrap().remove("launchAuthorityId");
    });
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("missing launch authority"),
        LocalProfileError::InvalidProfile
    );
}

#[cfg(not(unix))]
#[test]
fn rejects_local_profiles_until_native_owner_acl_validation_exists() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");

    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("unsupported ACL validation"),
        LocalProfileError::InsecurePermissions
    );
}

#[cfg(unix)]
#[test]
fn rejects_group_readable_profile() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    fs::set_permissions(&profile_path, fs::Permissions::from_mode(0o640))
        .expect("weaken profile permissions");
    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("insecure profile"),
        LocalProfileError::InsecurePermissions
    );
}

#[cfg(unix)]
#[test]
fn profile_missing_required_telemetry_capability_is_rejected() {
    let directory = tempfile::tempdir().expect("temp directory");
    let profile_path = write_profile(directory.path(), "https://127.0.0.1:43123");
    rewrite_profile(&profile_path, |profile| {
        let capabilities = profile["capabilities"]
            .as_array_mut()
            .expect("capabilities");
        capabilities.retain(|capability| capability != "runtime.operational-telemetry.v1");
        let capabilities = capabilities
            .iter()
            .map(|capability| capability.as_str().expect("capability string"))
            .collect::<Vec<_>>();
        profile["capabilityDigest"] =
            serde_json::json!(hex::encode(ordered_capability_digest(&capabilities)));
    });

    assert_eq!(
        LocalRuntimeProfile::load(&profile_path).expect_err("missing telemetry capability"),
        LocalProfileError::InvalidProfile
    );
}

#[test]
fn committed_bundle_hash_and_required_telemetry_capability_are_synchronized() {
    let bundle = include_bytes!("../../../contracts/gocode-ui-client-1/bundle.json");
    assert_eq!(hex::encode(Sha256::digest(bundle)), GOLDEN_BUNDLE_HASH);

    let bundle: serde_json::Value = serde_json::from_slice(bundle).expect("bundle JSON");
    let published_capabilities = bundle["publishedCapabilities"]
        .as_array()
        .expect("published capabilities")
        .iter()
        .map(|capability| capability.as_str().expect("capability string"))
        .collect::<Vec<_>>();
    assert_eq!(published_capabilities, REQUIRED_RUNTIME_CAPABILITIES);
    assert!(REQUIRED_RUNTIME_CAPABILITIES.contains(&"runtime.operational-telemetry.v1"));
}

#[test]
fn bootstrap_v3_wire_matches_schema_golden() {
    let schema = include_bytes!("../../../docs/schemas/local-session-v2.schema.json");
    let published_schema = include_bytes!(
        "../../../contracts/gocode-ui-client-1/schemas/local-session-v2.schema.json"
    );
    let golden = include_bytes!("../../../docs/golden/local-session-v2.json");
    let published_golden =
        include_bytes!("../../../contracts/gocode-ui-client-1/golden/local-session-v2.json");
    assert_eq!(schema, published_schema);
    assert_eq!(golden, published_golden);

    let schema: serde_json::Value = serde_json::from_slice(schema).unwrap();
    let golden: serde_json::Value = serde_json::from_slice(golden).unwrap();
    for definition in [
        "challengeRequest",
        "challengeResponse",
        "authenticateRequest",
        "authenticateResponse",
    ] {
        assert_eq!(schema["$defs"][definition]["additionalProperties"], false);
        assert_eq!(golden[definition]["wireVersion"], "3");
        assert_eq!(golden[definition]["keyVersion"], 1);
    }
    assert!(golden["challengeRequest"].get("serverNonce").is_none());
    assert!(golden["authenticateRequest"].get("proof").is_none());
    assert!(golden["authenticateRequest"]["finalProof"].is_string());
}

fn certificate_der() -> Vec<u8> {
    let mut parameters = CertificateParams::new(Vec::new()).expect("certificate parameters");
    parameters.subject_alt_names = vec![SanType::IpAddress(std::net::IpAddr::V4(
        Ipv4Addr::LOCALHOST,
    ))];
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
    parameters
        .self_signed(&key)
        .expect("certificate")
        .der()
        .to_vec()
}

fn ordered_capability_digest(capabilities: &[&str]) -> [u8; 32] {
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
fn secure(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure file");
}

#[cfg(not(unix))]
const fn secure(_: &std::path::Path) {}
