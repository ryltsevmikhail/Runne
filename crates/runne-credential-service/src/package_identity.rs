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

pub struct InstalledConfigurations {
    pub endpoints: [CredentialServiceEndpointConfiguration; 3],
    pub local_fixture: bool,
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

pub fn installed_configurations() -> Result<InstalledConfigurations, CredentialServiceXpcError> {
    #[cfg(target_os = "macos")]
    {
        let executable =
            std::env::current_exe().map_err(|_| CredentialServiceXpcError::Unavailable)?;
        let paths = package_executables(&executable)?;
        #[cfg(feature = "test-support")]
        if local_fixture_enabled(&executable) {
            return Ok(InstalledConfigurations {
                endpoints: local_configurations(&paths)?,
                local_fixture: true,
            });
        }
        let service = observe(&paths.service)?;
        let desktop = observe(&paths.desktop)?;
        let runtime = observe(&paths.runtime)?;
        let writer = observe(&paths.writer)?;
        Ok(InstalledConfigurations {
            endpoints: configurations(&service, &desktop, &runtime, &writer)?,
            local_fixture: false,
        })
    }
    #[cfg(not(target_os = "macos"))]
    Err(CredentialServiceXpcError::Unsupported)
}

#[cfg(all(feature = "test-support", target_os = "macos"))]
fn local_configurations(
    paths: &PackageExecutables,
) -> Result<[CredentialServiceEndpointConfiguration; 3], CredentialServiceXpcError> {
    let roles = [
        (&paths.service, "dev.runne.slice-e.credential-service"),
        (&paths.desktop, "dev.runne.slice-e.desktop"),
        (&paths.runtime, "dev.runne.slice-e.daemon"),
        (&paths.writer, "dev.runne.slice-e.writer"),
    ];
    let observed = roles
        .iter()
        .map(|(path, expected)| {
            let identity = observe_local(path)?;
            if identity.identifier != *expected {
                return Err(CredentialServiceXpcError::Rejected);
            }
            Ok(identity)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if observed.iter().enumerate().any(|(index, identity)| {
        observed[..index]
            .iter()
            .any(|prior| prior.cdhash == identity.cdhash)
    }) {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let service = local_requirement(roles[0].0, roles[0].1)?;
    let clients = [
        (CredentialServiceEndpointRole::Desktop, roles[1]),
        (CredentialServiceEndpointRole::Runtime, roles[2]),
        (CredentialServiceEndpointRole::Writer, roles[3]),
    ];
    clients
        .map(|(role, (path, identifier))| {
            CredentialServiceEndpointConfiguration::new(
                role,
                role.endpoint_name(),
                service.clone(),
                local_requirement(path, identifier)?,
            )
        })
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .try_into()
        .map_err(|_| CredentialServiceXpcError::Rejected)
}

#[cfg(all(feature = "test-support", target_os = "macos"))]
fn local_requirement(
    path: &Path,
    expected_identifier: &str,
) -> Result<CredentialServicePeerRequirement, CredentialServiceXpcError> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "-r", "-", "--"])
        .arg(path)
        .output()
        .map_err(|_| CredentialServiceXpcError::Unavailable)?;
    if !output.status.success() {
        return Err(CredentialServiceXpcError::Rejected);
    }
    let requirement = std::str::from_utf8(&output.stdout)
        .map_err(|_| CredentialServiceXpcError::Rejected)?
        .lines()
        .find_map(|line| {
            line.strip_prefix("designated => ")
                .or_else(|| line.strip_prefix("# designated => "))
        })
        .ok_or(CredentialServiceXpcError::Rejected)?;
    CredentialServicePeerRequirement::from_local_designated_requirement(
        expected_identifier,
        requirement,
    )
}

#[cfg(all(feature = "test-support", target_os = "macos"))]
fn local_fixture_enabled(executable: &Path) -> bool {
    let Some(root) = std::env::var_os("RUNNE_SLICE_E_FIXTURE_ROOT")
        .and_then(|path| std::fs::canonicalize(path).ok())
    else {
        return false;
    };
    let home = std::env::var_os("HOME").and_then(|path| std::fs::canonicalize(path).ok());
    let keychain = std::env::var_os("RUNNE_CI_MACOS_KEYCHAIN")
        .and_then(|path| std::fs::canonicalize(path).ok());
    let current = std::fs::canonicalize(executable).ok();
    std::env::var_os("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST").as_deref()
        == Some(std::ffi::OsStr::new("1"))
        && std::env::var_os("RUNNE_SLICE_E_SCENARIO").as_deref()
            == Some(std::ffi::OsStr::new("service-joined"))
        && home.as_deref() == Some(root.join("home").as_path())
        && keychain.as_deref()
            == Some(
                root.join("home/Library/Keychains/runne-ci.keychain-db")
                    .as_path(),
            )
        && current.as_deref()
            == Some(
                root.join("Runne.app/Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service")
                    .as_path(),
            )
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
#[cfg(all(feature = "test-support", target_os = "macos"))]
use native::observe_local;

#[cfg(test)]
#[path = "package_identity/tests.rs"]
mod tests;
