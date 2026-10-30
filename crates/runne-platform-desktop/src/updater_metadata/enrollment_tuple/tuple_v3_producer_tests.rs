use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{
    MacOsCodeIdentityExpectationV1, NativeEnrollmentTupleV3CodeIdentities,
    NativeEnrollmentTupleV3Digests, UpdateTargetV2,
    enrollment_tuple_v3_producer::{CodeIdentityObserver, CodeIdentityRole, produce_with_observer},
};

const ENTITLEMENTS: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>com.apple.application-identifier</key>
  <string>758F9Z45SR.com.runne.credential-service</string>
  <key>com.apple.developer.team-identifier</key>
  <string>758F9Z45SR</string>
  <key>keychain-access-groups</key>
  <array>
    <string>758F9Z45SR.com.runne.credential-service</string>
  </array>
</dict>
</plist>
"#;
const PROTOCOL: &[u8] = br#"{"schemaVersion":1,"transport":"nsxpc","compatibilityBundles":[{"registrationWire":1,"registrationAuthSuite":1,"providerFrameWire":2,"providerGrantAuth":1,"runtimeEnvelopeWire":2,"runtimeRequestAuth":3,"runtimeReplyAuth":3}]}"#;
const LAUNCH_AGENT: &[u8] = br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.runne.credential-service</string>
  <key>BundleProgram</key>
  <string>Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service</string>
  <key>KeepAlive</key>
  <false/>
  <key>RunAtLoad</key>
  <false/>
  <key>MachServices</key>
  <dict>
    <key>com.runne.credential-service.desktop.v1</key>
    <true/>
    <key>com.runne.credential-service.runtime.v1</key>
    <true/>
    <key>com.runne.credential-service.writer.v1</key>
    <true/>
  </dict>
</dict>
</plist>
"#;

pub(in crate::updater_metadata) struct Fixture {
    _directory: tempfile::TempDir,
    pub(in crate::updater_metadata) app: PathBuf,
    pub(in crate::updater_metadata) target: UpdateTargetV2,
}

impl Fixture {
    pub(in crate::updater_metadata) fn exact() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let app = directory.path().join("Runne.app");
        let contents = app.join("Contents");
        let macos = contents.join("MacOS");
        let resources = contents.join("Resources");
        let native = resources.join("native-enrollment");
        let helper = contents.join("Library/Helpers/RunneCredentialService.app/Contents/MacOS");
        let launch = contents.join("Library/LaunchAgents");
        let profile = helper.parent().unwrap().join("embedded.provisionprofile");
        let contract = resources.join("contracts/gocode-ui-client-3/bundle.json");
        for directory in [
            &macos,
            &native,
            &helper,
            &launch,
            contract.parent().unwrap(),
        ] {
            std::fs::create_dir_all(directory).unwrap();
        }
        for (path, bytes) in [
            (macos.join("runne-desktop"), b"desktop".as_slice()),
            (macos.join("runne"), b"writer".as_slice()),
            (macos.join("runned"), b"daemon".as_slice()),
            (
                helper.join("runne-credential-service"),
                b"service".as_slice(),
            ),
            (profile, b"distribution-profile".as_slice()),
            (contract, b"contract-v2".as_slice()),
            (
                launch.join("com.runne.credential-service.plist"),
                LAUNCH_AGENT,
            ),
            (
                native.join("credential-service.entitlements.plist"),
                ENTITLEMENTS,
            ),
            (native.join("xpc-protocol-v1.json"), PROTOCOL),
        ] {
            std::fs::write(path, bytes).unwrap();
        }
        #[cfg(unix)]
        for name in ["runne-desktop", "runne", "runned"] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(macos.join(name), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                helper.join("runne-credential-service"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let mut target = target();
        let bytes = format!(
            "{{\"arch\":\"{}\",\"platform\":\"{}\",\"productId\":\"{}\",\"profileId\":\"{}\",\"releaseCandidateSha256\":\"{}\",\"schemaVersion\":1,\"version\":\"{}\"}}",
            target.arch,
            target.platform,
            target.product_id,
            target.profile_id,
            "0".repeat(64),
            target.version,
        )
        .into_bytes();
        let path = native.join("release-candidate-binding.json");
        std::fs::write(&path, &bytes).unwrap();
        target.release_candidate_sha256 = "0".repeat(64);
        Self {
            _directory: directory,
            app,
            target,
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.app.join(relative)
    }
}

pub(in crate::updater_metadata) struct FixedObserver;

impl CodeIdentityObserver for FixedObserver {
    fn verify_bundle(&self, _path: &Path) -> Result<(), super::NativeEnrollmentTupleError> {
        Ok(())
    }

    fn observe(
        &self,
        role: CodeIdentityRole,
        _path: &Path,
    ) -> Result<MacOsCodeIdentityExpectationV1, super::NativeEnrollmentTupleError> {
        let (identifier, byte) = match role {
            CodeIdentityRole::Desktop => ("com.runne.desktop", '1'),
            CodeIdentityRole::Writer => ("runne", '2'),
            CodeIdentityRole::Daemon => ("runned", '3'),
            CodeIdentityRole::CredentialService => ("com.runne.credential-service", '4'),
        };
        MacOsCodeIdentityExpectationV1::new(identifier, "758F9Z45SR", byte.to_string().repeat(40))
            .ok_or(super::NativeEnrollmentTupleError::Rejected)
    }
}

#[test]
fn producer_hashes_exact_fixed_artifacts_and_emits_tuple_v3() {
    let fixture = Fixture::exact();
    let tuple = produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).unwrap();
    let value = serde_json::to_value(tuple).unwrap();
    let digests: NativeEnrollmentTupleV3Digests =
        serde_json::from_value(value["digests"].clone()).unwrap();
    assert_eq!(
        digests.candidate_sha256,
        fixture.target.release_candidate_sha256
    );
    assert_eq!(digests.desktop_sha256, digest(b"desktop"));
    assert_eq!(digests.writer_sha256, digest(b"writer"));
    assert_eq!(digests.daemon_sha256, digest(b"daemon"));
    assert_eq!(digests.credential_service_sha256, digest(b"service"));
    assert_eq!(digests.launch_agent_plist_sha256, digest(LAUNCH_AGENT));
    assert_eq!(digests.entitlements_sha256, digest(ENTITLEMENTS));
    assert_eq!(digests.provisioning_sha256, digest(b"distribution-profile"));
    assert_eq!(digests.xpc_protocol_sha256, digest(PROTOCOL));
    assert_eq!(digests.contract_sha256, digest(b"contract-v2"));
    assert_eq!(
        value["deployment"]["helperBundleIdentifier"],
        "com.runne.credential-service"
    );
    assert_eq!(
        value["deployment"]["runtimeMachService"],
        "com.runne.credential-service.runtime.v1"
    );
    let _: NativeEnrollmentTupleV3CodeIdentities =
        serde_json::from_value(value["codeIdentities"].clone()).unwrap();
}

#[test]
fn producer_rejects_missing_or_noncanonical_bound_artifacts() {
    for relative in [
        "Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
        "Contents/Library/LaunchAgents/com.runne.credential-service.plist",
        "Contents/Resources/native-enrollment/credential-service.entitlements.plist",
        "Contents/Resources/native-enrollment/xpc-protocol-v1.json",
        "Contents/Resources/native-enrollment/release-candidate-binding.json",
        "Contents/Resources/contracts/gocode-ui-client-3/bundle.json",
    ] {
        let fixture = Fixture::exact();
        std::fs::remove_file(fixture.path(relative)).unwrap();
        assert!(
            produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).is_err(),
            "{relative}"
        );
    }
    for relative in [
        "Contents/Library/LaunchAgents/com.runne.credential-service.plist",
        "Contents/Resources/native-enrollment/credential-service.entitlements.plist",
        "Contents/Resources/native-enrollment/xpc-protocol-v1.json",
    ] {
        let fixture = Fixture::exact();
        std::fs::write(fixture.path(relative), b"changed").unwrap();
        assert!(
            produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).is_err(),
            "{relative}"
        );
    }
}

#[test]
fn producer_rejects_noncanonical_or_wrong_target_candidate_binding() {
    let fixture = Fixture::exact();
    let path = fixture.path("Contents/Resources/native-enrollment/release-candidate-binding.json");
    let bytes = std::fs::read(&path).unwrap();
    std::fs::write(&path, [bytes.as_slice(), b"\n"].concat()).unwrap();
    assert!(produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).is_err());

    let fixture = Fixture::exact();
    let mut target = fixture.target.clone();
    target.version = "9.9.9".into();
    assert!(produce_with_observer(&fixture.app, &target, &FixedObserver).is_err());
}

#[cfg(unix)]
#[test]
fn producer_rejects_symlinked_and_hardlinked_artifacts() {
    use std::os::unix::fs::symlink;
    let fixture = Fixture::exact();
    let protocol = fixture.path("Contents/Resources/native-enrollment/xpc-protocol-v1.json");
    let replacement = fixture.path("protocol-replacement");
    std::fs::rename(&protocol, &replacement).unwrap();
    symlink(&replacement, &protocol).unwrap();
    assert!(produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).is_err());

    let fixture = Fixture::exact();
    let service = fixture.path("Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service");
    std::fs::hard_link(&service, fixture.path("service-copy")).unwrap();
    assert!(produce_with_observer(&fixture.app, &fixture.target, &FixedObserver).is_err());
}

fn target() -> UpdateTargetV2 {
    UpdateTargetV2 {
        product_id: "com.runne.desktop".into(),
        version: "1.2.3".into(),
        platform: "macos".into(),
        arch: "arm64".into(),
        artifact_sha256: "a".repeat(64),
        artifact_size: 10,
        artifact_url: "https://updates.example.test/Runne.dmg".into(),
        release_candidate_sha256: String::new(),
        min_os: "13.0".into(),
        profile_id: "gocode-ui-client/3".into(),
        bundle_sha256: digest(b"contract-v2"),
        runtime_version: "0.1.0".into(),
        runtime_digest: "b".repeat(64),
        channel: "stable".into(),
        published_at_unix_seconds: 100,
        expires_at_unix_seconds: 500,
        rollback_floor: "1.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
