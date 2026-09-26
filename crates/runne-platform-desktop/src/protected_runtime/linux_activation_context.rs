//! Read-only activation measurements from the retained protected process.
use super::{
    BundledRuntimeLifecycleState, ProtectedBundledRuntimeError, ProtectedBundledRuntimeSupervisor,
    ProtectedProcessActivation,
};
use runne_api::provider_credential_enrollment::linux_activation_policy::{
    LinuxInstallationFacts, LinuxInstallationLayout,
};
use std::path::{Path, PathBuf};

impl ProtectedBundledRuntimeSupervisor {
    /// Measures the live installation for the Linux preprompt policy.
    ///
    /// Authority comes from the verified readiness transcript, never from
    /// an approval record or a guessed sidecar. These facts grant no writer
    /// authority; the later operation and qualification fences still apply.
    ///
    /// # Errors
    /// Rejects absent, unready, stopped, substituted, or unmeasurable processes.
    pub fn linux_activation_context(
        &mut self,
    ) -> Result<(PathBuf, LinuxInstallationFacts), ProtectedBundledRuntimeError> {
        if self.state != BundledRuntimeLifecycleState::Ready || self.pending_profile.is_some() {
            return Err(ProtectedBundledRuntimeError::InvalidState);
        }
        let process = self
            .process
            .as_mut()
            .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)?;
        if process.graceful_requested
            || process
                .child
                .try_wait()
                .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
                .is_some()
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        let (root, authority, expected_daemon) = activation_binding(&process.activation)
            .ok_or(ProtectedBundledRuntimeError::InvalidState)?;
        if root != self.spec.runtime_root()
            || std::fs::canonicalize(root).ok().as_deref() != Some(root)
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        super::validate_owner_private_directory(root)?;
        let daemon_image = PathBuf::from(format!("/proc/{}/exe", process.child.id()));
        std::fs::canonicalize(&daemon_image)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let desktop_image = Path::new("/proc/self/exe");
        let desktop = std::fs::canonicalize(desktop_image)
            .map_err(|_| ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let writer = package_writer_for_desktop(&desktop)
            .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
        let facts = measure(
            &LinuxInstallationLayout {
                runtime_root: root,
                desktop_image,
                writer_image: &writer,
                daemon_image: &daemon_image,
                machine_id_path: Path::new("/etc/machine-id"),
            },
            authority,
            expected_daemon,
        )?;
        if process
            .child
            .try_wait()
            .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?
            .is_some()
        {
            return Err(ProtectedBundledRuntimeError::OwnershipMismatch);
        }
        Ok((root.to_path_buf(), facts))
    }
}

fn package_writer_for_desktop(desktop: &Path) -> Option<PathBuf> {
    let desktop = desktop.canonicalize().ok()?;
    let writer = desktop.parent()?.join("runne");
    let metadata = std::fs::symlink_metadata(&writer).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || writer.canonicalize().ok()?.as_path() != writer
    {
        return None;
    }
    Some(writer)
}

fn measure(
    layout: &LinuxInstallationLayout<'_>,
    authority: [u8; 16],
    expected_daemon: [u8; 32],
) -> Result<LinuxInstallationFacts, ProtectedBundledRuntimeError> {
    let facts = layout
        .canonicalize_facts(authority)
        .ok_or(ProtectedBundledRuntimeError::ExecutableIdentityMismatch)?;
    if facts.daemon_image_digest != expected_daemon {
        return Err(ProtectedBundledRuntimeError::ExecutableIdentityMismatch);
    }
    Ok(facts)
}

fn activation_binding(
    activation: &ProtectedProcessActivation,
) -> Option<(&Path, [u8; 16], [u8; 32])> {
    match activation {
        ProtectedProcessActivation::V2 { request, owned, .. } => Some((
            request.compatibility_request().runtime_root(),
            *owned.compatibility_owned_launch().stable().authority_id(),
            *request
                .compatibility_request()
                .executable()
                .executable_sha256(),
        )),
        ProtectedProcessActivation::V3 { request, owned, .. } => Some((
            request.runtime_root(),
            *owned.stable().authority_id(),
            *request.executable().executable_sha256(),
        )),
        ProtectedProcessActivation::V1 { .. } => None,
        #[cfg(feature = "test-support")]
        ProtectedProcessActivation::Test { .. } => None,
    }
}

#[cfg(test)]
mod tests;
