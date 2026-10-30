//! Launch-time installation source selection and post-ready image rebind.
//!
//! The published record witnesses config, layout and exact images. A rebuilt
//! product at the same install paths may start only while every predecessor byte
//! is still retained; the record is rewritten after authenticated ready.
use super::*;

/// The published source plus a permitted in-place image transition.
///
/// A rebuilt CLI/daemon at the same exact install paths is the normal product
/// update. The launch may proceed on the newly measured images only when the
/// config, layout and every predecessor byte are still the adopted ones; the
/// record itself is rewritten after authenticated ready.
pub(crate) struct InstallationLaunchSource {
    pub(crate) current: Option<TerminalSource>,
    pub(crate) image_upgrade: Option<(TerminalSource, TerminalSource)>,
}

pub(crate) fn prepare_launch(
    state: &ActivationStateStore,
) -> Result<InstallationLaunchSource, ProtectedBundledRuntimeError> {
    let Some(source) = state.read_record::<TerminalSource>(RECORD)? else {
        return Ok(InstallationLaunchSource {
            current: None,
            image_upgrade: None,
        });
    };
    if source.validate().is_ok() {
        return Ok(InstallationLaunchSource {
            current: Some(source),
            image_upgrade: None,
        });
    }
    let invalid = ProtectedBundledRuntimeError::ActivationStateUnavailable;
    source.validate_layout()?;
    // The predecessor must still be the exact retained bytes this installation
    // staged; otherwise this is a different binary tree, not an in-place update.
    retained_image(state, &source.cli_image)?;
    retained_image(state, &source.daemon_image)?;
    retained_image(state, &source.host_image)?;
    let mut next = source.clone();
    next.cli_image = measured(&source.cli)?;
    next.daemon_image = measured(&source.daemon)?;
    next.host_image = measured(&source.host)?;
    next.validate()?;
    if next == source {
        return Err(invalid);
    }
    Ok(InstallationLaunchSource {
        current: Some(source.clone()),
        image_upgrade: Some((source, next)),
    })
}


/// Verifies the recorded predecessor is still present as a retained image.
fn retained_image(
    state: &ActivationStateStore,
    image: &StoredExecutableV1,
) -> Result<(), ProtectedBundledRuntimeError> {
    let identity = image.clone().into_contract()?;
    let name = format!(
        "{}-{}.runned",
        hex::encode(identity.executable_sha256()),
        identity.byte_length()
    );
    let path = state
        .directory
        .join(super::super::STAGED_EXECUTABLE_DIRECTORY)
        .join(name);
    super::super::validate_staged_executable(&path, &identity)
}

impl ActivationStateStore {
    /// Compare-and-swap replacement of the published images after signed ready.
    pub(crate) fn migrate_installation_images(
        &self,
        previous: &TerminalSource,
        next: &TerminalSource,
    ) -> Result<(), ProtectedBundledRuntimeError> {
        let invalid = ProtectedBundledRuntimeError::ActivationStateUnavailable;
        match self.read_record::<TerminalSource>(RECORD)? {
            Some(current) if &current == next => Ok(()),
            Some(current) if &current == previous => {
                let encoded = serde_json::to_vec(next).map_err(|_| invalid)?;
                if encoded.is_empty() || encoded.len() as u64 > super::super::MAX_STATE_BYTES {
                    return Err(invalid);
                }
                let temporary = self
                    .directory
                    .join(format!(".terminal-images-{}.tmp", uuid::Uuid::now_v7()));
                let result = (|| {
                    let mut file = OpenOptions::new()
                        .create_new(true)
                        .write(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW)
                        .open(&temporary)
                        .map_err(|_| invalid)?;
                    file.write_all(&encoded)
                        .and_then(|()| file.sync_all())
                        .map_err(|_| invalid)?;
                    std::fs::rename(&temporary, self.directory.join(RECORD))
                        .map_err(|_| invalid)?;
                    sync_directory(&self.directory)
                })();
                if result.is_err() && temporary.exists() {
                    let _ = std::fs::remove_file(&temporary);
                }
                result
            }
            _ => Err(invalid),
        }
    }
}
