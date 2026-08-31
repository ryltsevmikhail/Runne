use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use runne_platform_desktop::{
    StagedUpdate, UpdateCoordinator, UpdateInstallState, UpdateTargetBindingConfig,
    UpdateTrustRootV2, install_staged_update,
};
use serde::{Deserialize, Serialize};

use runne_update_metadata_producer::{ProducerError, UpdateMetadataDraft, UpdatePublicKeyManifest};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DemoConfig {
    schema_version: u32,
    metadata_endpoint: String,
    draft_path: PathBuf,
    public_manifest_path: PathBuf,
    profile_directory: PathBuf,
    current_executable: PathBuf,
    evidence_path: PathBuf,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DemoEvidence {
    schema_version: &'static str,
    transport: &'static str,
    current_version: String,
    installed_version: String,
    artifact_sha256: String,
    state_transitions: [&'static str; 4],
    pre_cutover_admission: [&'static str; 3],
    post_cutover_health: [&'static str; 3],
    external_command_templates: [&'static str; 6],
}

pub fn run(path: &Path) -> Result<(), ProducerError> {
    let config: DemoConfig = read_json(path)?;
    let draft: UpdateMetadataDraft = read_json(&config.draft_path)?;
    let manifest: UpdatePublicKeyManifest = read_json(&config.public_manifest_path)?;
    validate_config(&config, &draft, &manifest)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ProducerError::Verification)?;
    runtime.block_on(execute(&config, &draft, &manifest))
}

async fn execute(
    config: &DemoConfig,
    draft: &UpdateMetadataDraft,
    manifest: &UpdatePublicKeyManifest,
) -> Result<(), ProducerError> {
    let trust = trust_root(manifest)?;
    let binding = UpdateTargetBindingConfig {
        product_id: draft.product_id.clone(),
        platform: draft.platform.clone(),
        arch: draft.arch.clone(),
        min_os: draft.min_os.clone(),
        profile_id: draft.profile_id.clone(),
        bundle_sha256: draft.bundle_sha256.clone(),
        runtime_version: draft.runtime_version.clone(),
        runtime_digest: draft.runtime_digest.clone(),
        channel: draft.channel.clone(),
    };
    let coordinator =
        UpdateCoordinator::new_dev_loopback(trust, binding, &config.profile_directory)
            .map_err(|_| ProducerError::Verification)?;
    let update = coordinator
        .check(
            &config.metadata_endpoint,
            draft.published_at_unix_seconds,
            &draft.current_version,
            &draft.rollback_floor,
        )
        .await
        .map_err(|_| ProducerError::Verification)?;
    let staged = coordinator
        .stage(&update)
        .await
        .map_err(|_| ProducerError::Verification)?;
    require_state(staged.state, UpdateInstallState::Staged)?;
    let prepared = coordinator
        .prepare_restart(0, false)
        .map_err(|_| ProducerError::Verification)?;
    require_state(prepared.state, UpdateInstallState::RestartRequired)?;
    let artifact_sha256 = prepared.artifact_sha256.clone();
    install_staged_update(
        &StagedUpdate {
            path: prepared.staged_path,
            artifact_sha256: artifact_sha256.clone(),
        },
        &config.current_executable,
    )
    .map_err(|_| ProducerError::Verification)?;
    let checking = coordinator
        .begin_health_check()
        .map_err(|_| ProducerError::Verification)?;
    require_state(checking.state, UpdateInstallState::HealthCheck)?;
    post_cutover_health(&config.current_executable, &draft.version)?;
    let committed = coordinator
        .complete_health(true, &draft.version)
        .map_err(|_| ProducerError::Verification)?;
    require_state(committed.state, UpdateInstallState::Committed)?;
    publish_evidence(
        &config.evidence_path,
        &DemoEvidence {
            schema_version: "runne-update-demo-evidence.v1",
            transport: "debug-only exact IPv4 127.0.0.1; redirects disabled",
            current_version: draft.current_version.clone(),
            installed_version: draft.version.clone(),
            artifact_sha256,
            state_transitions: ["staged", "restart_required", "health_check", "committed"],
            pre_cutover_admission: [
                "component signatures accepted",
                "bundle signature accepted",
                "Gatekeeper accepted",
            ],
            post_cutover_health: [
                "installed version matched",
                "Gatekeeper accepted",
                "runtime doctor execution-ready",
            ],
            external_command_templates: [
                "/usr/bin/codesign --verify --strict <INSTALLED_EXECUTABLE>",
                "/usr/bin/codesign --verify --strict <INSTALLED_APP>",
                "/usr/sbin/spctl --assess --type execute <INSTALLED_APP>",
                "/usr/bin/plutil -extract CFBundleShortVersionString raw -o - <INFO_PLIST>",
                "<INSTALLED_APP>/Contents/MacOS/runne --version",
                "<INSTALLED_APP>/Contents/MacOS/runned doctor",
            ],
        },
    )
}

fn post_cutover_health(executable: &Path, expected_version: &str) -> Result<(), ProducerError> {
    let bundle = executable
        .ancestors()
        .find(|path| path.extension().and_then(|value| value.to_str()) == Some("app"))
        .ok_or(ProducerError::Verification)?;
    let macos = bundle.join("Contents/MacOS");
    for name in ["runne-desktop", "runne", "runned"] {
        success(Command::new("/usr/bin/codesign").args([
            "--verify",
            "--strict",
            macos.join(name).to_string_lossy().as_ref(),
        ]))?;
    }
    success(Command::new("/usr/bin/codesign").args([
        "--verify",
        "--strict",
        bundle.to_string_lossy().as_ref(),
    ]))?;
    success(Command::new("/usr/sbin/spctl").args([
        "--assess",
        "--type",
        "execute",
        bundle.to_string_lossy().as_ref(),
    ]))?;
    let version = Command::new("/usr/bin/plutil")
        .args(["-extract", "CFBundleShortVersionString", "raw", "-o", "-"])
        .arg(bundle.join("Contents/Info.plist"))
        .output()
        .map_err(|_| ProducerError::Verification)?;
    if !version.status.success()
        || String::from_utf8(version.stdout)
            .map_err(|_| ProducerError::Verification)?
            .trim()
            != expected_version
    {
        return Err(ProducerError::Verification);
    }
    success(Command::new(macos.join("runne")).arg("--version"))?;
    success(Command::new(macos.join("runned")).arg("doctor"))
}

fn success(command: &mut Command) -> Result<(), ProducerError> {
    command
        .status()
        .map_err(|_| ProducerError::Verification)?
        .success()
        .then_some(())
        .ok_or(ProducerError::Verification)
}

fn trust_root(manifest: &UpdatePublicKeyManifest) -> Result<UpdateTrustRootV2, ProducerError> {
    Ok(UpdateTrustRootV2::from_keys(
        [
            (&manifest.root_a_id, key(&manifest.root_a_hex)?),
            (&manifest.root_b_id, key(&manifest.root_b_hex)?),
            (&manifest.root_c_id, key(&manifest.root_c_hex)?),
        ],
        (&manifest.timestamp_id, key(&manifest.timestamp_hex)?),
        (&manifest.snapshot_id, key(&manifest.snapshot_hex)?),
    ))
}

fn key(value: &str) -> Result<[u8; 32], ProducerError> {
    let bytes = hex::decode(value).map_err(|_| ProducerError::Input)?;
    bytes.try_into().map_err(|_| ProducerError::Input)
}

fn require_state(
    actual: UpdateInstallState,
    expected: UpdateInstallState,
) -> Result<(), ProducerError> {
    (actual == expected)
        .then_some(())
        .ok_or(ProducerError::Verification)
}

fn validate_config(
    config: &DemoConfig,
    draft: &UpdateMetadataDraft,
    manifest: &UpdatePublicKeyManifest,
) -> Result<(), ProducerError> {
    if config.schema_version != 1
        || manifest.schema_version != 1
        || !config.profile_directory.is_absolute()
        || !config.current_executable.is_absolute()
        || !config.evidence_path.is_absolute()
        || config.evidence_path.exists()
        || draft.current_version == draft.version
    {
        return Err(ProducerError::Input);
    }
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, ProducerError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ProducerError::Input)?;
    if !metadata.file_type().is_file() || metadata.len() > 512 * 1024 {
        return Err(ProducerError::Input);
    }
    let bytes = fs::read(path).map_err(|_| ProducerError::Input)?;
    serde_json::from_slice(&bytes).map_err(|_| ProducerError::Input)
}

fn publish_evidence(path: &Path, evidence: &DemoEvidence) -> Result<(), ProducerError> {
    let bytes = serde_json::to_vec_pretty(&evidence).map_err(|_| ProducerError::Output)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| ProducerError::Output)?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| ProducerError::Output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_parser_requires_exactly_32_bytes() {
        assert_eq!(key(&"00".repeat(32)).unwrap(), [0; 32]);
        assert_eq!(key(&"00".repeat(31)), Err(ProducerError::Input));
        assert_eq!(key("zz"), Err(ProducerError::Input));
    }
}
