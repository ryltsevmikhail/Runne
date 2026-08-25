use std::path::Path;

use runne_platform_desktop::{UpdateCoordinator, UpdateTargetBindingConfig, UpdateTrustRootV2};

pub struct CompiledUpdater {
    pub(crate) endpoint: &'static str,
    pub(crate) rollback_floor: &'static str,
    pub(crate) coordinator: UpdateCoordinator,
}

impl CompiledUpdater {
    #[allow(clippy::similar_names)]
    pub fn load(profile_directory: &Path) -> Option<Self> {
        let endpoint = option_env!("RUNNE_UPDATE_METADATA_ENDPOINT")?;
        let rollback_floor = option_env!("RUNNE_UPDATE_ROLLBACK_FLOOR")?;
        let root_a_id = option_env!("RUNNE_UPDATE_ROOT_A_ID")?;
        let root_b_id = option_env!("RUNNE_UPDATE_ROOT_B_ID")?;
        let root_c_id = option_env!("RUNNE_UPDATE_ROOT_C_ID")?;
        let timestamp_id = option_env!("RUNNE_UPDATE_TIMESTAMP_ID")?;
        let snapshot_id = option_env!("RUNNE_UPDATE_SNAPSHOT_ID")?;
        let profile_id = option_env!("RUNNE_UPDATE_PROFILE_ID")?;
        let bundle_sha256 = option_env!("RUNNE_UPDATE_BUNDLE_SHA256")?;
        let runtime_version = option_env!("RUNNE_UPDATE_RUNTIME_VERSION")?;
        let runtime_digest = option_env!("RUNNE_UPDATE_RUNTIME_DIGEST")?;
        let channel = option_env!("RUNNE_UPDATE_CHANNEL")?;
        let root_a = key(option_env!("RUNNE_UPDATE_ROOT_A_HEX")?)?;
        let root_b = key(option_env!("RUNNE_UPDATE_ROOT_B_HEX")?)?;
        let root_c = key(option_env!("RUNNE_UPDATE_ROOT_C_HEX")?)?;
        let timestamp = key(option_env!("RUNNE_UPDATE_TIMESTAMP_HEX")?)?;
        let snapshot = key(option_env!("RUNNE_UPDATE_SNAPSHOT_HEX")?)?;
        let trust = UpdateTrustRootV2::from_keys(
            [
                (root_a_id, root_a),
                (root_b_id, root_b),
                (root_c_id, root_c),
            ],
            (timestamp_id, timestamp),
            (snapshot_id, snapshot),
        );
        let coordinator = UpdateCoordinator::new(
            trust,
            UpdateTargetBindingConfig {
                product_id: "com.runne.desktop".into(),
                platform: platform().into(),
                arch: architecture().into(),
                min_os: minimum_os().into(),
                profile_id: profile_id.into(),
                bundle_sha256: bundle_sha256.into(),
                runtime_version: runtime_version.into(),
                runtime_digest: runtime_digest.into(),
                channel: channel.into(),
            },
            profile_directory,
        )
        .ok()?;
        Some(Self {
            endpoint,
            rollback_floor,
            coordinator,
        })
    }
}

fn key(value: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(value).ok()?;
    bytes.try_into().ok()
}

const fn platform() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    }
}

const fn architecture() -> &'static str {
    if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        "x86_64"
    }
}

const fn minimum_os() -> &'static str {
    if cfg!(target_os = "windows") {
        "windows-10-22h2"
    } else if cfg!(target_os = "macos") {
        "macos-13"
    } else {
        "ubuntu-22.04"
    }
}
