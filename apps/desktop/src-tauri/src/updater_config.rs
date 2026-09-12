use std::path::Path;

use runne_platform_desktop::{
    CompiledUpdateTrustRootV2, UpdateCoordinator, UpdateTargetBindingConfig,
};

pub struct CompiledUpdater {
    pub(crate) endpoint: Option<&'static str>,
    pub(crate) rollback_floor: Option<&'static str>,
    pub(crate) coordinator: UpdateCoordinator,
}

impl CompiledUpdater {
    #[must_use]
    pub fn load(profile_directory: &Path) -> Option<Self> {
        Self::load_remote(profile_directory).or_else(|| {
            #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
            { Some(Self {
                endpoint: None, rollback_floor: None,
                coordinator: UpdateCoordinator::for_current_installed_release(profile_directory)?,
            }) }
            #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
            { None }
        })
    }

    fn load_remote(profile_directory: &Path) -> Option<Self> {
        let endpoint = option_env!("RUNNE_UPDATE_METADATA_ENDPOINT")?;
        let rollback_floor = option_env!("RUNNE_UPDATE_ROLLBACK_FLOOR")?;
        let profile_id = option_env!("RUNNE_UPDATE_PROFILE_ID")?;
        let bundle_sha256 = option_env!("RUNNE_UPDATE_BUNDLE_SHA256")?;
        let runtime_version = option_env!("RUNNE_UPDATE_RUNTIME_VERSION")?;
        let runtime_digest = option_env!("RUNNE_UPDATE_RUNTIME_DIGEST")?;
        let channel = option_env!("RUNNE_UPDATE_CHANNEL")?;
        let (platform, arch, min_os) = current_target()?;
        let binding = UpdateTargetBindingConfig {
            product_id: "com.runne.desktop".into(),
            platform: platform.into(),
            arch: arch.into(),
            min_os: min_os.into(),
            profile_id: profile_id.into(),
            bundle_sha256: bundle_sha256.into(),
            runtime_version: runtime_version.into(),
            runtime_digest: runtime_digest.into(),
            channel: channel.into(),
        };
        #[cfg(all(feature = "dev-loopback-updater", debug_assertions))]
        let coordinator = UpdateCoordinator::new_dev_loopback(
            CompiledUpdateTrustRootV2::load()?.into_trust_root(),
            binding,
            profile_directory,
        )
        .ok()?;
        #[cfg(not(all(feature = "dev-loopback-updater", debug_assertions)))]
        let coordinator = UpdateCoordinator::new(
            CompiledUpdateTrustRootV2::load()?.into_trust_root(),
            binding,
            profile_directory,
        )
        .ok()?;
        Some(Self {
            endpoint: Some(endpoint),
            rollback_floor: Some(rollback_floor),
            coordinator,
        })
    }
}

const fn current_target() -> Option<(&'static str, &'static str, &'static str)> {
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Some(("macos", "arm64", "macos-13"))
    } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
        Some(("macos", "x86_64", "macos-13"))
    } else if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        Some(("windows", "x86_64", "windows-10-22h2"))
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        Some(("linux", "x86_64", "ubuntu-22.04"))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::current_target;

    #[test]
    fn compiled_updater_target_exactly_matches_the_build() {
        #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
        assert_eq!(current_target(), Some(("macos", "arm64", "macos-13")));
        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        assert_eq!(current_target(), Some(("macos", "x86_64", "macos-13")));
        #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
        assert_eq!(
            current_target(),
            Some(("windows", "x86_64", "windows-10-22h2"))
        );
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        assert_eq!(current_target(), Some(("linux", "x86_64", "ubuntu-22.04")));
        #[cfg(not(any(
            all(target_os = "macos", target_arch = "aarch64"),
            all(target_os = "macos", target_arch = "x86_64"),
            all(target_os = "windows", target_arch = "x86_64"),
            all(target_os = "linux", target_arch = "x86_64"),
        )))]
        assert_eq!(current_target(), None);
    }
}
