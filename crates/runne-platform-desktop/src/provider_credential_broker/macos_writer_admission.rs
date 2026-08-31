use std::fs::File;
use std::num::NonZeroU32;
use std::os::unix::fs::FileExt as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::str::FromStr as _;

use ed25519_dalek::SigningKey;
use rand::{RngCore as _, rngs::OsRng};
use runne_platform_ports::provider_credential_broker::BrokerHandoffError;
#[cfg(test)]
use runne_platform_ports::provider_credential_broker::VerifiedWriterArtifact;
use security_framework::os::macos::code_signing::{
    Flags, GuestAttributes, SecCode, SecRequirement,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::{RetainedWriterProcess, UnixRetainedWriterProcess, WriterProcessEvidence};
use crate::VerifiedMacOsWriterLaunch;

pub(super) fn verify_live_writer(
    process: &UnixRetainedWriterProcess,
    launch: &VerifiedMacOsWriterLaunch,
    image: &RetainedMacOsWriterImage,
    channel_binding: [u8; 32],
    publication_public_key: [u8; 32],
    writer_kill_public_key: [u8; 32],
) -> Result<WriterProcessEvidence, BrokerHandoffError> {
    if channel_binding == [0; 32] || publication_public_key == [0; 32] {
        return Err(BrokerHandoffError::Rejected);
    }
    let start = process.writer_start_identity()?;
    let pid = process.pid();
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    let code = SecCode::copy_guest_with_attribues(None, &attributes, Flags::NONE)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let requirement = SecRequirement::from_str(&launch.code_requirement())
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let flags = Flags::STRICT_VALIDATE | Flags::NO_NETWORK_ACCESS;
    code.check_validity(flags, &requirement)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    let live_path = code
        .path(Flags::NONE)
        .ok()
        .and_then(|value| value.to_path())
        .ok_or(BrokerHandoffError::Rejected)?;
    let live_path = std::fs::canonicalize(live_path).map_err(|_| BrokerHandoffError::Rejected)?;
    let pid = NonZeroU32::new(pid.cast_unsigned()).ok_or(BrokerHandoffError::Rejected)?;
    let executable =
        runne_macos_process_identity::MacOsProcessExecutableIdentity::observe(pid, &live_path)
            .map_err(|_| BrokerHandoffError::Rejected)?;
    if live_path != image.path
        || !executable.matches_file(&image.metadata)
        || !image.matches_current_path_and_digest()?
        || process.writer_start_identity()? != start
    {
        return Err(BrokerHandoffError::Rejected);
    }
    WriterProcessEvidence::from_verified_macos_writer(
        start,
        image.digest,
        launch.launch().artifact().release_tuple_digest(),
        channel_binding,
        publication_public_key,
        writer_kill_public_key,
    )
}

/// Exact retained writer validated against one signed macOS release tuple.
pub struct VerifiedMacOsWriterProcess {
    process: Option<UnixRetainedWriterProcess>,
    image: RetainedMacOsWriterImage,
    launch: VerifiedMacOsWriterLaunch,
    evidence: WriterProcessEvidence,
    kill_signing_key: Option<SigningKey>,
}

impl VerifiedMacOsWriterProcess {
    pub(super) fn admit(
        mut process: UnixRetainedWriterProcess,
        launch: VerifiedMacOsWriterLaunch,
        image: RetainedMacOsWriterImage,
        channel_binding: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> Result<Self, BrokerHandoffError> {
        let mut signing_seed = Zeroizing::new([0_u8; 32]);
        if OsRng.try_fill_bytes(&mut *signing_seed).is_err() {
            let _ = process.terminate_retained_child();
            let _ = process.reap_retained_child();
            return Err(BrokerHandoffError::Unavailable);
        }
        let kill_signing_key = SigningKey::from_bytes(&signing_seed);
        let evidence = match verify_live_writer(
            &process,
            &launch,
            &image,
            channel_binding,
            publication_public_key,
            kill_signing_key.verifying_key().to_bytes(),
        ) {
            Ok(evidence) => evidence,
            Err(error) => {
                let _ = process.terminate_retained_child();
                let _ = process.reap_retained_child();
                return Err(error);
            }
        };
        Ok(Self {
            process: Some(process),
            image,
            launch,
            evidence,
            kill_signing_key: Some(kill_signing_key),
        })
    }

    pub(super) fn refresh_evidence(&mut self) -> Result<(), BrokerHandoffError> {
        let process = self.process.as_ref().ok_or(BrokerHandoffError::Rejected)?;
        self.evidence = verify_live_writer(
            process,
            &self.launch,
            &self.image,
            self.evidence.channel,
            self.evidence
                .publication_public_key
                .ok_or(BrokerHandoffError::Rejected)?,
            self.kill_signing_key
                .as_ref()
                .ok_or(BrokerHandoffError::Rejected)?
                .verifying_key()
                .to_bytes(),
        )?;
        Ok(())
    }

    pub(super) const fn evidence(&self) -> &WriterProcessEvidence {
        &self.evidence
    }

    pub(super) fn into_reap_only(
        mut self,
    ) -> Result<(super::unix::UnixWriterReapOnlyProcess, SigningKey), BrokerHandoffError> {
        let process = self
            .process
            .take()
            .ok_or(BrokerHandoffError::Rejected)?
            .into_reap_only();
        let signing_key = self
            .kill_signing_key
            .take()
            .ok_or(BrokerHandoffError::Rejected)?;
        Ok((process, signing_key))
    }

    #[cfg(test)]
    pub(super) fn matches_handoff(
        &self,
        channel_binding: [u8; 32],
        publication_public_key: [u8; 32],
    ) -> bool {
        self.evidence.matches_daemon_owned_launch(
            self.launch.launch(),
            channel_binding,
            publication_public_key,
        )
    }
}

impl std::fmt::Debug for VerifiedMacOsWriterProcess {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedMacOsWriterProcess(<retained>)")
    }
}

impl Drop for VerifiedMacOsWriterProcess {
    fn drop(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.terminate_retained_child();
            let _ = process.reap_retained_child();
        }
    }
}

pub(super) struct RetainedMacOsWriterImage {
    file: File,
    metadata: std::fs::Metadata,
    path: PathBuf,
    digest: [u8; 32],
}

pub(super) fn prepare_retained_writer_image(
    launch: &VerifiedMacOsWriterLaunch,
) -> Result<RetainedMacOsWriterImage, BrokerHandoffError> {
    let image = RetainedMacOsWriterImage::open(launch.launch().executable())?;
    (image.digest == launch.launch().artifact().image_digest())
        .then_some(image)
        .ok_or(BrokerHandoffError::Rejected)
}

#[cfg(test)]
pub(super) fn test_retained_writer_image(
    path: &Path,
) -> Result<RetainedMacOsWriterImage, BrokerHandoffError> {
    RetainedMacOsWriterImage::open(path)
}

impl RetainedMacOsWriterImage {
    fn open(path: &Path) -> Result<Self, BrokerHandoffError> {
        let before = std::fs::symlink_metadata(path).map_err(|_| BrokerHandoffError::Rejected)?;
        if !before.file_type().is_file() || before.file_type().is_symlink() || before.nlink() != 1 {
            return Err(BrokerHandoffError::Rejected);
        }
        let file = File::open(path).map_err(|_| BrokerHandoffError::Rejected)?;
        let opened = file.metadata().map_err(|_| BrokerHandoffError::Rejected)?;
        if opened.dev() != before.dev() || opened.ino() != before.ino() || opened.nlink() != 1 {
            return Err(BrokerHandoffError::Rejected);
        }
        let after = std::fs::symlink_metadata(path).map_err(|_| BrokerHandoffError::Rejected)?;
        if after.dev() != opened.dev() || after.ino() != opened.ino() || after.nlink() != 1 {
            return Err(BrokerHandoffError::Rejected);
        }
        Ok(Self {
            digest: hash_open_file(&file)?,
            file,
            metadata: opened,
            path: std::fs::canonicalize(path).map_err(|_| BrokerHandoffError::Rejected)?,
        })
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    fn matches_current_path_and_digest(&self) -> Result<bool, BrokerHandoffError> {
        let current =
            std::fs::symlink_metadata(&self.path).map_err(|_| BrokerHandoffError::Rejected)?;
        Ok(current.file_type().is_file()
            && !current.file_type().is_symlink()
            && current.dev() == self.metadata.dev()
            && current.ino() == self.metadata.ino()
            && current.nlink() == 1
            && hash_open_file(&self.file)? == self.digest)
    }
}

fn hash_open_file(file: &File) -> Result<[u8; 32], BrokerHandoffError> {
    let mut hasher = Sha256::new();
    let mut chunk = [0_u8; 16 * 1024];
    let mut offset = 0_u64;
    loop {
        let read = file
            .read_at(&mut chunk, offset)
            .map_err(|_| BrokerHandoffError::Rejected)?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
        offset = offset
            .checked_add(u64::try_from(read).map_err(|_| BrokerHandoffError::Rejected)?)
            .ok_or(BrokerHandoffError::Rejected)?;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
pub(super) fn test_apple_launch(
    path: &Path,
    release_tuple: [u8; 32],
) -> Result<VerifiedMacOsWriterLaunch, BrokerHandoffError> {
    let retained = RetainedMacOsWriterImage::open(path)?;
    let path = retained.path.clone();
    let image = retained.digest;
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-r", "-", "--"])
        .arg(&path)
        .output()
        .map_err(|_| BrokerHandoffError::Unavailable)?;
    if !output.status.success() {
        return Err(BrokerHandoffError::Rejected);
    }
    let stdout = std::str::from_utf8(&output.stdout).map_err(|_| BrokerHandoffError::Rejected)?;
    let requirement = stdout
        .lines()
        .find_map(|line| {
            line.strip_prefix("designated => ")
                .or_else(|| line.strip_prefix("# designated => "))
        })
        .ok_or(BrokerHandoffError::Rejected)?
        .to_owned();
    let artifact = VerifiedWriterArtifact::new(path, image, release_tuple)
        .map_err(|_| BrokerHandoffError::Rejected)?;
    Ok(VerifiedMacOsWriterLaunch::test_only(artifact, requirement))
}
