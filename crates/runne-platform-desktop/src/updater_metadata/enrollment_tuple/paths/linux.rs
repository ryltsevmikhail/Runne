use super::super::enrollment_measurement::OpenedNativeEnrollmentFile;
use super::{NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError};
use std::{
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

const CONTRACT_RELATIVE: &[&str] = &["contracts", "gocode-ui-client-3", "bundle.json"];

#[path = "linux_admission.rs"]
mod linux_admission;
#[path = "linux_rooted_file.rs"]
mod linux_rooted_file;
pub(super) use linux_rooted_file::open_rooted_path;
use linux_rooted_file::validate_relative;

impl NativeEnrollmentArtifactPathsV1 {
    /// Resolves the installed Linux package from Tauri's locator paths.
    pub(crate) fn resolve_linux_from_host_paths(
        desktop_executable: &Path,
        resource_directory: &Path,
    ) -> Result<Self, NativeEnrollmentTupleError> {
        resolve_from_host_paths(desktop_executable, resource_directory)
    }

    pub(in crate::updater_metadata) fn resolve_linux_from_authenticated_peer(
        stream: &UnixStream,
        resource_directory_hint: &Path,
    ) -> Result<(Self, LinuxAuthenticatedDesktopPeer), NativeEnrollmentTupleError> {
        resolve_from_authenticated_peer(stream, resource_directory_hint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxAuthenticatedDesktopPeer {
    pid: u32,
    uid: u32,
    start_ticks: u64,
    executable: PathBuf,
}

impl LinuxAuthenticatedDesktopPeer {
    pub(super) fn capture(stream: &UnixStream) -> Result<Self, NativeEnrollmentTupleError> {
        let peer = rustix::net::sockopt::socket_peercred(stream)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let pid = u32::try_from(peer.pid.as_raw_pid())
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        if pid == 0 || pid == std::process::id() || peer.uid != rustix::process::geteuid() {
            return Err(NativeEnrollmentTupleError::Rejected);
        }
        let executable = std::fs::canonicalize(format!("/proc/{pid}/exe"))
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        let value = Self {
            pid,
            uid: peer.uid.as_raw(),
            start_ticks: process_start_ticks(pid)?,
            executable,
        };
        value.revalidate(stream)?;
        Ok(value)
    }

    pub(super) fn executable(&self) -> &Path {
        &self.executable
    }

    pub(super) const fn pid(&self) -> u32 {
        self.pid
    }

    pub(super) fn revalidate(&self, stream: &UnixStream) -> Result<(), NativeEnrollmentTupleError> {
        let peer = rustix::net::sockopt::socket_peercred(stream)
            .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
        (u32::try_from(peer.pid.as_raw_pid()).ok() == Some(self.pid)
            && peer.uid.as_raw() == self.uid
            && process_start_ticks(self.pid)? == self.start_ticks
            && std::fs::canonicalize(format!("/proc/{}/exe", self.pid))
                .map_err(|_| NativeEnrollmentTupleError::Rejected)?
                == self.executable)
            .then_some(())
            .ok_or(NativeEnrollmentTupleError::Rejected)
    }
}

fn process_start_ticks(pid: u32) -> Result<u64, NativeEnrollmentTupleError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|ticks| ticks.parse().ok())
        .ok_or(NativeEnrollmentTupleError::Rejected)
}

pub(super) fn resolve_from_authenticated_peer(
    stream: &UnixStream,
    resource_directory_hint: &Path,
) -> Result<
    (
        NativeEnrollmentArtifactPathsV1,
        LinuxAuthenticatedDesktopPeer,
    ),
    NativeEnrollmentTupleError,
> {
    let peer = LinuxAuthenticatedDesktopPeer::capture(stream)?;
    let desktop = peer.executable().to_path_buf();
    if desktop
        .file_name()
        .is_none_or(|name| name != "runne-desktop")
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let bin_dir = desktop
        .parent()
        .ok_or(NativeEnrollmentTupleError::Rejected)?;
    let writer = canonical_file(&bin_dir.join("runne"))?;
    let daemon = canonical_file(&bin_dir.join("runned"))?;
    let resource = std::fs::canonicalize(resource_directory_hint)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if resource != resource_directory_hint {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let mut contract = resource;
    for component in CONTRACT_RELATIVE {
        contract.push(component);
    }
    let contract = canonical_file(&contract)?;
    let paths = capture_paths(&[desktop.clone(), writer, daemon, contract], false)?;
    let peer_exe = std::fs::File::open(format!("/proc/{}/exe", peer.pid()))
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if !paths.desktop_file.matches_file(&peer_exe)? {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    peer.revalidate(stream)?;
    Ok((paths, peer))
}

pub(super) fn resolve_from_host_paths(
    desktop_executable: &Path,
    resource_directory: &Path,
) -> Result<NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError> {
    let desktop = canonical_file(desktop_executable)?;
    if desktop
        != std::fs::canonicalize(
            std::env::current_exe().map_err(|_| NativeEnrollmentTupleError::Rejected)?,
        )
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?
        || desktop
            .file_name()
            .is_none_or(|name| name != "runne-desktop")
    {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let resource = std::fs::canonicalize(resource_directory)
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let bin_dir = desktop
        .parent()
        .ok_or(NativeEnrollmentTupleError::Rejected)?;
    let writer = canonical_file(&bin_dir.join("runne"))?;
    let daemon = canonical_file(&bin_dir.join("runned"))?;
    let mut contract = resource;
    for component in CONTRACT_RELATIVE {
        contract.push(component);
    }
    let contract = canonical_file(&contract)?;
    capture_paths(&[desktop, writer, daemon, contract], true)
}

fn capture_paths(
    paths: &[PathBuf; 4],
    live_desktop: bool,
) -> Result<NativeEnrollmentArtifactPathsV1, NativeEnrollmentTupleError> {
    let root = common_parent(paths)?;
    let relative: [PathBuf; 4] = paths
        .iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
            validate_relative(relative)?;
            Ok(relative.to_path_buf())
        })
        .collect::<Result<Vec<_>, NativeEnrollmentTupleError>>()?
        .try_into()
        .map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    let root_fd = super::open_absolute_directory(&root)?;
    let desktop_file = OpenedNativeEnrollmentFile::new(open_rooted_path(&root_fd, &relative[0])?)?;
    let writer_file = OpenedNativeEnrollmentFile::new(open_rooted_path(&root_fd, &relative[1])?)?;
    let daemon_file = OpenedNativeEnrollmentFile::new(open_rooted_path(&root_fd, &relative[2])?)?;
    let contract_file = OpenedNativeEnrollmentFile::new(open_rooted_path(&root_fd, &relative[3])?)?;
    let paths = NativeEnrollmentArtifactPathsV1 {
        desktop: paths[0].clone(),
        writer: paths[1].clone(),
        application: root,
        root: root_fd,
        relative_files: Some(relative),
        desktop_file,
        writer_file,
        daemon_file,
        contract_file,
        live_desktop,
    };
    paths.confirm_current()?;
    Ok(paths)
}

fn canonical_file(path: &Path) -> Result<PathBuf, NativeEnrollmentTupleError> {
    if !path.is_absolute() {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    let canonical =
        std::fs::canonicalize(path).map_err(|_| NativeEnrollmentTupleError::Rejected)?;
    if canonical != path {
        return Err(NativeEnrollmentTupleError::Rejected);
    }
    Ok(canonical)
}

fn common_parent(paths: &[PathBuf; 4]) -> Result<PathBuf, NativeEnrollmentTupleError> {
    let mut candidate = paths[0]
        .parent()
        .ok_or(NativeEnrollmentTupleError::Rejected)?;
    while !paths.iter().all(|path| path.starts_with(candidate)) {
        candidate = candidate
            .parent()
            .ok_or(NativeEnrollmentTupleError::Rejected)?;
    }
    Ok(candidate.to_path_buf())
}

impl NativeEnrollmentArtifactPathsV1 {
    pub(super) fn revalidate_linux_entries(
        &self,
        relative: &[PathBuf; 4],
    ) -> Result<(), NativeEnrollmentTupleError> {
        let captured = [
            &self.desktop_file,
            &self.writer_file,
            &self.daemon_file,
            &self.contract_file,
        ];
        captured
            .iter()
            .zip(relative)
            .try_for_each(|(captured, path)| {
                let current = open_rooted_path(&self.root, path)?;
                captured
                    .matches_file(&current)?
                    .then_some(())
                    .ok_or(NativeEnrollmentTupleError::Rejected)
            })
    }
}

#[cfg(test)]
#[path = "linux_tests.rs"]
mod tests;
