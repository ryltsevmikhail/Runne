//! Dev admission probe: verifies one issued `UpdateMetadataV2` against the
//! dev trust manifest and the staged signed `Runne.app`, then reports whether
//! the installed release admits a qualified native-enrollment candidate.
//!
//! This exercises the signed-metadata and tuple admission layer that the
//! desktop composition calls before code-identity confirmation. It is local
//! dev evidence, not release qualification.
//!
//! Example:
//! `cargo run -p runne-platform-desktop --example dev_installed_admission -- \
//!    --metadata target/dev-metadata/update/issued-metadata.json \
//!    --trust-manifest target/dev-metadata/dev-trust-manifest.json \
//!    --bundle target/dev-bundle/Runne.app`

use std::process::ExitCode;

#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use runne_platform_desktop::{
    NativeEnrollmentQualification, UpdateMetadataV2, UpdateTargetV2Binding, UpdateTrustRootV2,
    produce_staged_native_enrollment_tuple_v3, verify_update_v2,
};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
fn fail(message: &str) -> ExitCode {
    eprintln!("stage=admission status=err message={message}");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(target_os = "macos")]
struct TrustManifest {
    root_ids: [String; 3],
    root_keys: [[u8; 32]; 3],
    timestamp_id: String,
    timestamp_key: [u8; 32],
    snapshot_id: String,
    snapshot_key: [u8; 32],
}

#[cfg(target_os = "macos")]
fn trust_from_manifest(path: &Path) -> Result<UpdateTrustRootV2, String> {
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let text = |name: &str| {
        value
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("trust manifest is missing {name}"))
    };
    let key = |name: &str| {
        let encoded = text(name)?;
        hex::decode(encoded)
            .ok()
            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
            .ok_or_else(|| format!("trust manifest {name} is not a 32-byte key"))
    };
    let manifest = TrustManifest {
        root_ids: [text("rootAId")?, text("rootBId")?, text("rootCId")?],
        root_keys: [key("rootAHex")?, key("rootBHex")?, key("rootCHex")?],
        timestamp_id: text("timestampId")?,
        timestamp_key: key("timestampHex")?,
        snapshot_id: text("snapshotId")?,
        snapshot_key: key("snapshotHex")?,
    };
    let roots = [
        (manifest.root_ids[0].as_str(), manifest.root_keys[0]),
        (manifest.root_ids[1].as_str(), manifest.root_keys[1]),
        (manifest.root_ids[2].as_str(), manifest.root_keys[2]),
    ];
    Ok(UpdateTrustRootV2::from_keys(
        roots,
        (manifest.timestamp_id.as_str(), manifest.timestamp_key),
        (manifest.snapshot_id.as_str(), manifest.snapshot_key),
    ))
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let (mut metadata, mut trust, mut bundle) = (None, None, None);
    while let Some(flag) = arguments.next() {
        let value: PathBuf = PathBuf::from(
            arguments
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?,
        );
        match flag.as_str() {
            "--metadata" => metadata = Some(value),
            "--trust-manifest" => trust = Some(value),
            "--bundle" => bundle = Some(value),
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    let metadata = metadata.ok_or("missing --metadata")?;
    let trust = trust.ok_or("missing --trust-manifest")?;
    let bundle = bundle.ok_or("missing --bundle")?;
    let bundle =
        std::fs::canonicalize(&bundle).map_err(|error| format!("{}: {error}", bundle.display()))?;
    let metadata: UpdateMetadataV2 =
        serde_json::from_slice(&std::fs::read(&metadata).map_err(|error| error.to_string())?)
            .map_err(|error| format!("invalid UpdateMetadataV2: {error}"))?;
    let trust = trust_from_manifest(&trust)?;
    let target = metadata.targets.target.clone();
    let bundle_sha256 =
        sha256_hex(&bundle.join("Contents/Resources/contracts/gocode-ui-client-3/bundle.json"))?;
    let runtime_digest = sha256_hex(&bundle.join("Contents/MacOS/runned"))?;
    let mut produced = target.clone();
    produced.bundle_sha256.clone_from(&bundle_sha256);
    produced.runtime_digest.clone_from(&runtime_digest);
    let measured = produce_staged_native_enrollment_tuple_v3(&bundle, &produced)
        .map_err(|error| format!("bundle measurement failed: {error:?}"))?;
    let binding = UpdateTargetV2Binding {
        product_id: &target.product_id,
        platform: &target.platform,
        arch: &target.arch,
        min_os: &target.min_os,
        profile_id: &target.profile_id,
        bundle_sha256: &bundle_sha256,
        runtime_version: &target.runtime_version,
        runtime_digest: &runtime_digest,
        channel: &target.channel,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "clock".to_owned())?
        .as_secs();
    let verified = verify_update_v2(
        &metadata,
        &trust,
        &binding,
        now,
        &target.version,
        &target.rollback_floor,
    )
    .map_err(|error| format!("signed metadata rejected: {error:?}"))?;
    let admission = verified
        .admit_native_enrollment_v3(&measured)
        .ok_or_else(|| "installed bundle does not match the admitted tuple".to_owned())?;
    let qualified = matches!(
        admission.qualification(),
        NativeEnrollmentQualification::Qualified(_)
    );
    println!(
        "stage=admission status=ok qualified_admission={} bundleSha256={} runtimeDigest={}",
        if qualified { "some" } else { "none" },
        bundle_sha256,
        runtime_digest,
    );
    if !qualified {
        return Err("no qualified native-enrollment candidate".into());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => fail(&message),
    }
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("dev_installed_admission requires macOS and was not executed on this platform");
    ExitCode::from(2)
}
