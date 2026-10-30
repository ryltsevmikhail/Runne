//! Dev bring-up harness: measures one staged, signed dev `Runne.app` and emits
//! the produced `NativeEnrollmentTupleV3` as JSON for the local update-metadata
//! issuer (`runne-update-metadata-producer`).
//!
//! The bundle must already be assembled and Developer ID signed (see
//! `scripts/desktop/dev-signed-run.sh`). The caller supplies the update-artifact
//! facts that the tuple binds (digest, size, URL) and the compiled daemon policy
//! values (runtime version, channel); everything else is measured from the
//! signed bundle so the harness output is deterministic for one exact bundle.
//!
//! Example:
//! `cargo run -p runne-platform-desktop --example dev_enrollment_tuple -- \
//!    /abs/path/Runne.app /abs/tuple.json --artifact-sha256 <64-hex> \
//!    --artifact-size <bytes> --artifact-url https://.../Runne.dmg \
//!    --runtime-version 0.0.3 --channel dev`
//!
//! `--receipt PATH --qualified-at UNIX --qualification-expires UNIX` attaches
//! the local macOS qualification row. The three flags are all-or-nothing and
//! the receipt must bind this commit, artifact, and every measured input.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
use std::io::Write as _;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "macos")]
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};

#[cfg(target_os = "macos")]
use runne_platform_desktop::{NativeEnrollmentTupleV3, UpdateTargetV2};

#[cfg(target_os = "macos")]
use runne_platform_desktop::{
    produce_staged_native_enrollment_tuple_v3, produce_staged_native_enrollment_tuple_v3_qualified,
};

/// Mirrors the staged `release-candidate-binding.json` (camelCase on disk).
#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StagedReleaseCandidateBindingV1 {
    arch: String,
    platform: String,
    product_id: String,
    profile_id: String,
    release_candidate_sha256: String,
    schema_version: u32,
    version: String,
}

/// Harness output: the target the tuple binds plus the produced tuple itself.
#[cfg(target_os = "macos")]
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TupleHarnessOutputV1 {
    schema_version: u32,
    target: UpdateTargetV2,
    tuple: NativeEnrollmentTupleV3,
}

#[cfg(target_os = "macos")]
const MIN_OS: &str = "macos-13";

#[cfg(target_os = "macos")]
fn fail(stage: &str, message: &str) -> ExitCode {
    let _ = std::io::stdout().flush();
    eprintln!("stage={stage} status=err message={message}");
    ExitCode::from(1)
}

#[cfg(target_os = "macos")]
struct ArtifactFacts {
    sha256: String,
    size: u64,
    url: String,
}

#[cfg(target_os = "macos")]
struct PolicyFacts {
    runtime_version: String,
    channel: String,
}

#[cfg(target_os = "macos")]
struct QualificationFacts {
    receipt: PathBuf,
    qualified_at: u64,
    qualification_expires: u64,
}

#[cfg(target_os = "macos")]
fn parse_arguments() -> Result<
    (
        PathBuf,
        PathBuf,
        ArtifactFacts,
        PolicyFacts,
        Option<QualificationFacts>,
    ),
    String,
> {
    let mut arguments = std::env::args().skip(1);
    let candidate_app = arguments.next().ok_or("missing candidate app path")?;
    let output = arguments.next().ok_or("missing output json path")?;
    let mut artifact_sha256 = None;
    let mut artifact_size = None;
    let mut artifact_url = None;
    let mut runtime_version = None;
    let mut channel = None;
    let mut receipt = None;
    let mut qualified_at = None;
    let mut qualification_expires = None;
    while let Some(flag) = arguments.next() {
        let value = arguments
            .next()
            .ok_or_else(|| format!("missing value for {flag}"))?;
        match flag.as_str() {
            "--artifact-sha256" => artifact_sha256 = Some(value),
            "--artifact-size" => {
                artifact_size = Some(value.parse::<u64>().map_err(|_| "invalid artifact size")?);
            }
            "--artifact-url" => artifact_url = Some(value),
            "--runtime-version" => runtime_version = Some(value),
            "--channel" => channel = Some(value),
            "--receipt" => receipt = Some(PathBuf::from(value)),
            "--qualified-at" => {
                qualified_at = Some(value.parse::<u64>().map_err(|_| "invalid --qualified-at")?);
            }
            "--qualification-expires" => {
                qualification_expires = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "invalid --qualification-expires")?,
                );
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok((
        PathBuf::from(candidate_app),
        PathBuf::from(output),
        ArtifactFacts {
            sha256: artifact_sha256.ok_or("missing --artifact-sha256")?,
            size: artifact_size.ok_or("missing --artifact-size")?,
            url: artifact_url.ok_or("missing --artifact-url")?,
        },
        PolicyFacts {
            runtime_version: runtime_version.ok_or("missing --runtime-version")?,
            channel: channel.ok_or("missing --channel")?,
        },
        match (receipt, qualified_at, qualification_expires) {
            (None, None, None) => None,
            (Some(receipt), Some(qualified_at), Some(qualification_expires)) => {
                Some(QualificationFacts {
                    receipt,
                    qualified_at,
                    qualification_expires,
                })
            }
            _ => {
                return Err(
                    "--receipt, --qualified-at and --qualification-expires must be given together"
                        .into(),
                );
            }
        },
    ))
}

#[cfg(target_os = "macos")]
fn sha256_hex(path: &Path) -> Result<String, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("{}: {error}", path.display()))?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

#[cfg(target_os = "macos")]
fn load_staged_binding(candidate_app: &Path) -> Result<StagedReleaseCandidateBindingV1, String> {
    let path =
        candidate_app.join("Contents/Resources/native-enrollment/release-candidate-binding.json");
    let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    let binding: StagedReleaseCandidateBindingV1 =
        serde_json::from_slice(&bytes).map_err(|error| format!("{}: {error}", path.display()))?;
    (binding.schema_version == 1)
        .then_some(binding)
        .ok_or_else(|| format!("{}: unsupported schema version", path.display()))
}

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    let (candidate_app, output, artifact, policy, qualification) = match parse_arguments() {
        Ok(parsed) => parsed,
        Err(message) => return fail("arguments", &message),
    };
    let candidate_app = match candidate_app.canonicalize() {
        Ok(path) => path,
        Err(error) => return fail("candidate-app", &error.to_string()),
    };
    let binding = match load_staged_binding(&candidate_app) {
        Ok(binding) => binding,
        Err(message) => return fail("staged-binding", &message),
    };
    let contract =
        candidate_app.join("Contents/Resources/contracts/gocode-ui-client-3/bundle.json");
    let daemon = candidate_app.join("Contents/MacOS/runned");
    let (bundle_sha256, runtime_digest) = match (sha256_hex(&contract), sha256_hex(&daemon)) {
        (Ok(bundle), Ok(runtime)) => (bundle, runtime),
        (Err(message), _) | (_, Err(message)) => return fail("measure", &message),
    };
    let target = UpdateTargetV2 {
        product_id: binding.product_id.clone(),
        version: binding.version.clone(),
        platform: binding.platform.clone(),
        arch: binding.arch.clone(),
        artifact_sha256: artifact.sha256,
        artifact_size: artifact.size,
        artifact_url: artifact.url,
        release_candidate_sha256: binding.release_candidate_sha256.clone(),
        min_os: MIN_OS.into(),
        profile_id: binding.profile_id,
        bundle_sha256,
        runtime_version: policy.runtime_version,
        runtime_digest,
        channel: policy.channel,
        published_at_unix_seconds: 0,
        expires_at_unix_seconds: u64::MAX,
        rollback_floor: "0.0.0".into(),
        native_enrollment_tuple: None,
        native_enrollment_tuple_v3: None,
        qualification_bootstrap_client_v1: None,
    };
    let produced = match qualification {
        Some(qualification) => produce_staged_native_enrollment_tuple_v3_qualified(
            &candidate_app,
            &target,
            &qualification.receipt,
            qualification.qualified_at,
            qualification.qualification_expires,
        ),
        None => produce_staged_native_enrollment_tuple_v3(&candidate_app, &target),
    };
    let tuple = match produced {
        Ok(tuple) => tuple,
        Err(error) => return fail("produce", &format!("{error:?}")),
    };
    let produced = TupleHarnessOutputV1 {
        schema_version: 1,
        target,
        tuple,
    };
    let mut bytes = match serde_json::to_vec_pretty(&produced) {
        Ok(bytes) => bytes,
        Err(error) => return fail("serialize", &error.to_string()),
    };
    bytes.push(b'\n');
    if let Err(error) = std::fs::write(&output, &bytes) {
        return fail("write-output", &error.to_string());
    }
    let qualified = serde_json::to_value(&produced.tuple)
        .ok()
        .is_some_and(|value| value.get("nativeEnrollmentQualification").is_some());
    println!(
        "stage=produce status=ok output={} bundleSha256={} runtimeDigest={} qualified={}",
        output.display(),
        produced.target.bundle_sha256,
        produced.target.runtime_digest,
        qualified,
    );
    ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("dev_enrollment_tuple requires macOS and was not executed on this platform");
    ExitCode::from(2)
}
