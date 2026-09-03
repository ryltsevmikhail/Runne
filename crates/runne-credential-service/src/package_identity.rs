use std::path::{Path, PathBuf};

use runne_macos_xpc::{
    CredentialServiceEndpointConfiguration, CredentialServiceEndpointRole,
    CredentialServicePeerRequirement, CredentialServiceXpcError,
};

const TEAM_ID: &str = "758F9Z45SR";

struct PackageExecutables {
    service: PathBuf,
    desktop: PathBuf,
    runtime: PathBuf,
    writer: PathBuf,
}

#[derive(Clone)]
struct ObservedIdentity {
    identifier: String,
    team_identifier: String,
    cdhash: [u8; 20],
}

impl ObservedIdentity {
    fn requirement(
        &self,
        expected_identifier: &str,
    ) -> Result<CredentialServicePeerRequirement, CredentialServiceXpcError> {
        if self.identifier != expected_identifier || self.team_identifier != TEAM_ID {
            return Err(CredentialServiceXpcError::Rejected);
        }
        CredentialServicePeerRequirement::new(format!(
            "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\" and cdhash H\"{}\"",
            self.identifier,
            self.team_identifier,
            hex::encode(self.cdhash),
        ))
    }
}

pub fn installed_configurations()
-> Result<[CredentialServiceEndpointConfiguration; 3], CredentialServiceXpcError> {
    #[cfg(target_os = "macos")]
    {
        let executable =
            std::env::current_exe().map_err(|_| CredentialServiceXpcError::Unavailable)?;
        let paths = package_executables(&executable)?;
        let service = observe(&paths.service)?;
        let desktop = observe(&paths.desktop)?;
        let runtime = observe(&paths.runtime)?;
        let writer = observe(&paths.writer)?;
        configurations(&service, &desktop, &runtime, &writer)
    }
    #[cfg(not(target_os = "macos"))]
    Err(CredentialServiceXpcError::Unsupported)
}

fn configurations(
    service: &ObservedIdentity,
    desktop: &ObservedIdentity,
    runtime: &ObservedIdentity,
    writer: &ObservedIdentity,
) -> Result<[CredentialServiceEndpointConfiguration; 3], CredentialServiceXpcError> {
    let hashes = [
        service.cdhash,
        desktop.cdhash,
        runtime.cdhash,
        writer.cdhash,
    ];
    if hashes
        .iter()
        .enumerate()
        .any(|(index, hash)| hashes[..index].contains(hash))
    {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let service = service.requirement("com.runne.credential-service")?;
    let clients = [
        (
            CredentialServiceEndpointRole::Desktop,
            desktop.requirement("com.runne.desktop")?,
        ),
        (
            CredentialServiceEndpointRole::Runtime,
            runtime.requirement("runned")?,
        ),
        (
            CredentialServiceEndpointRole::Writer,
            writer.requirement("runne")?,
        ),
    ];
    let mut built = Vec::with_capacity(3);
    for (role, client) in clients {
        built.push(CredentialServiceEndpointConfiguration::new(
            role,
            role.endpoint_name(),
            service.clone(),
            client,
        )?);
    }
    built
        .try_into()
        .map_err(|_| CredentialServiceXpcError::Rejected)
}

fn package_executables(service: &Path) -> Result<PackageExecutables, CredentialServiceXpcError> {
    let macos = exact_parent(service, "runne-credential-service", "MacOS")?;
    let helper_contents = exact_parent(&macos, "MacOS", "Contents")?;
    let helper = exact_parent(&helper_contents, "Contents", "RunneCredentialService.app")?;
    let helpers = exact_parent(&helper, "RunneCredentialService.app", "Helpers")?;
    let library = exact_parent(&helpers, "Helpers", "Library")?;
    let contents = exact_parent(&library, "Library", "Contents")?;
    let app = exact_parent(&contents, "Contents", "Runne.app")?;
    Ok(PackageExecutables {
        service: service.to_path_buf(),
        desktop: app.join("Contents/MacOS/runne-desktop"),
        runtime: app.join("Contents/MacOS/runned"),
        writer: app.join("Contents/MacOS/runne"),
    })
}

fn exact_parent(
    path: &Path,
    expected_name: &str,
    expected_parent: &str,
) -> Result<PathBuf, CredentialServiceXpcError> {
    if path.file_name().and_then(|value| value.to_str()) != Some(expected_name) {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let parent = path.parent().ok_or(CredentialServiceXpcError::Rejected)?;
    if parent.file_name().and_then(|value| value.to_str()) != Some(expected_parent) {
        return Err(CredentialServiceXpcError::Rejected);
    }
    Ok(parent.to_path_buf())
}

#[cfg(target_os = "macos")]
#[path = "package_identity/native.rs"]
mod native;
#[cfg(target_os = "macos")]
use native::observe;

#[cfg(test)]
#[path = "package_identity/tests.rs"]
mod tests;
