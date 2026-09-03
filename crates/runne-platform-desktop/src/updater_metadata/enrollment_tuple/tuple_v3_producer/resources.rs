use runne_api::{
    NativeEnrollmentTupleError, NativeEnrollmentTupleV3ProtocolCompatibility,
    NativeEnrollmentTupleV3ProtocolVersions, UpdateTargetV2,
};
use serde::{Deserialize, Serialize};

use super::super::enrollment_measurement::OpenedNativeEnrollmentFile;

const MAX_RESOURCE_BYTES: u64 = 64 * 1024;
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
const XPC_PROTOCOL: &[u8] = br#"{"schemaVersion":1,"transport":"nsxpc","compatibilityBundles":[{"registrationWire":1,"registrationAuthSuite":1,"providerFrameWire":2,"providerGrantAuth":1,"runtimeEnvelopeWire":2,"runtimeRequestAuth":3,"runtimeReplyAuth":3}]}"#;

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReleaseCandidateBindingV1 {
    arch: String,
    platform: String,
    product_id: String,
    profile_id: String,
    release_candidate_sha256: String,
    schema_version: u32,
    version: String,
}

pub(super) struct ValidatedTupleV3Resources {
    pub(super) release_candidate_sha256: String,
    pub(super) protocol_versions: NativeEnrollmentTupleV3ProtocolVersions,
}

pub(super) fn validate_resources(
    launch_agent: &OpenedNativeEnrollmentFile,
    entitlements: &OpenedNativeEnrollmentFile,
    xpc_protocol: &OpenedNativeEnrollmentFile,
    candidate: &OpenedNativeEnrollmentFile,
    target: &UpdateTargetV2,
) -> Result<ValidatedTupleV3Resources, NativeEnrollmentTupleError> {
    exact(launch_agent, LAUNCH_AGENT)?;
    exact(entitlements, ENTITLEMENTS)?;
    exact(xpc_protocol, XPC_PROTOCOL)?;
    let bytes = candidate.read_bytes(MAX_RESOURCE_BYTES)?;
    let binding: ReleaseCandidateBindingV1 =
        serde_json::from_slice(&bytes).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let canonical =
        serde_json::to_vec(&binding).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let matches = bytes == canonical
        && binding.schema_version == 1
        && binding.product_id == target.product_id
        && binding.version == target.version
        && binding.platform == target.platform
        && binding.arch == target.arch
        && binding.profile_id == target.profile_id
        && binding.release_candidate_sha256 == target.release_candidate_sha256;
    matches
        .then(|| ValidatedTupleV3Resources {
            release_candidate_sha256: binding.release_candidate_sha256,
            protocol_versions: NativeEnrollmentTupleV3ProtocolVersions::new(vec![
                NativeEnrollmentTupleV3ProtocolCompatibility::new(1, 1, 2, 1, 2, 3, 3),
            ]),
        })
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

fn exact(
    file: &OpenedNativeEnrollmentFile,
    expected: &[u8],
) -> Result<(), NativeEnrollmentTupleError> {
    (file.read_bytes(MAX_RESOURCE_BYTES)? == expected)
        .then_some(())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}
