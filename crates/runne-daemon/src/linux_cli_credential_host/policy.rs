use crate::config::{ConfigurationSnapshot, LinuxCliCredentialHostConfig};
use runne_secure_store::ProviderCredentialAccessPolicy;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub type HostResult<T> = Result<T, &'static str>;

pub struct ImagePolicy {
    pub cli: PathBuf,
    pub daemon: PathBuf,
    pub host: PathBuf,
    pub cli_digest: [u8; 32],
    pub daemon_digest: [u8; 32],
    pub host_digest: [u8; 32],
    pub manifest: [u8; 32],
    config_digest: String,
    config_path: PathBuf,
}

impl ImagePolicy {
    pub fn load(config: &ConfigurationSnapshot) -> HostResult<Self> {
        let current = std::env::current_exe()
            .map_err(|_| "host image unavailable")?
            .canonicalize()
            .map_err(|_| "host image unavailable")?;
        let directory = current.parent().ok_or("host directory unavailable")?;
        Self::load_for_paths(
            config,
            crate::config::external_config_path(),
            directory.join("runne"),
            directory.join("runned"),
            directory.join("runne-credential-host"),
        )
    }

    /// Measures owner-controlled images against an already checked config snapshot.
    /// This is an image policy, not signed release qualification or enrollment authority.
    pub fn load_for_paths(
        config: &ConfigurationSnapshot,
        config_path: PathBuf,
        cli: PathBuf,
        daemon: PathBuf,
        host: PathBuf,
    ) -> HostResult<Self> {
        let pins = config
            .linux_cli_credential_host
            .as_ref()
            .ok_or("CLI credential host is not enabled")?;
        let cli_digest = image_digest(&cli)?;
        let daemon_digest = image_digest(&daemon)?;
        let host_digest = image_digest(&host)?;
        validate_pins(pins, cli_digest, daemon_digest, host_digest)?;
        let mut hash = Sha256::new();
        hash.update(b"runne/linux-cli-credential-host/policy/v1\0");
        hash.update(cli_digest);
        hash.update(daemon_digest);
        hash.update(host_digest);
        hash.update(config.digest.as_bytes());
        Ok(Self {
            cli,
            daemon,
            host,
            host_digest,
            cli_digest,
            daemon_digest,
            manifest: hash.finalize().into(),
            config_digest: config.digest.clone(),
            config_path,
        })
    }

    pub fn revalidate(&self) -> HostResult<()> {
        let config = crate::config::load_external_config_at(&self.config_path)
            .map_err(|_| "credential host configuration changed")?;
        if config.digest != self.config_digest {
            return Err("credential host configuration changed");
        }
        let live =
            std::fs::metadata("/proc/self/exe").map_err(|_| "live host image unavailable")?;
        let installed =
            std::fs::metadata(&self.daemon).map_err(|_| "installed host image unavailable")?;
        let host =
            std::fs::metadata(&self.host).map_err(|_| "installed credential host unavailable")?;
        if (live.dev(), live.ino()) != (installed.dev(), installed.ino())
            && (live.dev(), live.ino()) != (host.dev(), host.ino())
        {
            return Err("running host image differs from installed image");
        }
        if image_digest(&self.cli)? != self.cli_digest
            || image_digest(&self.daemon)? != self.daemon_digest
            || image_digest(&self.host)? != self.host_digest
        {
            return Err("credential host image changed");
        }
        Ok(())
    }

    pub fn access(&self) -> HostResult<ProviderCredentialAccessPolicy> {
        self.revalidate()?;
        ProviderCredentialAccessPolicy::new(&self.host, &self.daemon)
            .map_err(|_| "credential host access denied")
    }
}

fn validate_pins(
    pins: &LinuxCliCredentialHostConfig,
    cli: [u8; 32],
    daemon: [u8; 32],
    host: [u8; 32],
) -> HostResult<()> {
    if hex::decode(&pins.cli_sha256).ok().as_deref() != Some(cli.as_slice())
        || hex::decode(&pins.daemon_sha256).ok().as_deref() != Some(daemon.as_slice())
        || hex::decode(&pins.host_sha256).ok().as_deref() != Some(host.as_slice())
    {
        return Err("credential host image pins do not match");
    }
    Ok(())
}

fn image_digest(path: &Path) -> HostResult<[u8; 32]> {
    if path.canonicalize().ok().as_deref() != Some(path) {
        return Err("credential host image is aliased");
    }
    for parent in path.ancestors().skip(1) {
        let metadata =
            std::fs::symlink_metadata(parent).map_err(|_| "host directory unavailable")?;
        if !metadata.is_dir()
            || metadata.mode() & 0o022 != 0
            || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
        {
            return Err("host directory is not owner controlled");
        }
    }
    let mut file = File::options()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| "credential host image unavailable")?;
    let metadata = file
        .metadata()
        .map_err(|_| "credential host image unavailable")?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o100 == 0
        || metadata.nlink() != 1
    {
        return Err("credential host image is not owner controlled");
    }
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|_| "credential host image unavailable")?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let after = file
        .metadata()
        .map_err(|_| "credential host image unavailable")?;
    if (
        metadata.ino(),
        metadata.dev(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    ) != (
        after.ino(),
        after.dev(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) {
        return Err("credential host image changed during measurement");
    }
    Ok(hash.finalize().into())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
