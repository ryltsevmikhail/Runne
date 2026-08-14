use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::super::super::CliError;

pub(super) struct ProcessConfig {
    pub(super) executable: PathBuf,
    pub(super) path: OsString,
}

pub(super) fn discover() -> Result<ProcessConfig, CliError> {
    let executable = discover_git()?;
    let path = executable
        .parent()
        .ok_or(CliError::AuthorityGit)?
        .as_os_str()
        .to_owned();
    Ok(ProcessConfig { executable, path })
}

pub(super) fn fixed_environment(path: OsString) -> Vec<(&'static str, OsString)> {
    vec![
        ("LC_ALL", "C".into()),
        ("GIT_CONFIG_NOSYSTEM", "1".into()),
        ("GIT_CONFIG_GLOBAL", null_config().into()),
        ("GIT_NO_REPLACE_OBJECTS", "1".into()),
        ("GIT_NO_LAZY_FETCH", "1".into()),
        ("GIT_TERMINAL_PROMPT", "0".into()),
        ("GIT_OPTIONAL_LOCKS", "0".into()),
        ("GIT_LITERAL_PATHSPECS", "1".into()),
        ("GIT_PAGER", "cat".into()),
        ("PATH", path),
    ]
}

#[cfg(unix)]
fn discover_git() -> Result<PathBuf, CliError> {
    let preferred = Path::new("/usr/bin/git");
    if is_executable(preferred) {
        return preferred.canonicalize().map_err(|_| CliError::AuthorityGit);
    }
    discover_from_path("git")
}

#[cfg(windows)]
fn discover_git() -> Result<PathBuf, CliError> {
    for candidate in [
        r"C:\Program Files\Git\cmd\git.exe",
        r"C:\Program Files\Git\bin\git.exe",
        r"C:\Program Files (x86)\Git\cmd\git.exe",
    ] {
        let candidate = Path::new(candidate);
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|_| CliError::AuthorityGit);
        }
    }
    discover_from_path("git.exe")
}

#[cfg(not(any(unix, windows)))]
fn discover_git() -> Result<PathBuf, CliError> {
    Err(CliError::AuthorityGit)
}

fn discover_from_path(name: &str) -> Result<PathBuf, CliError> {
    let paths = env::var_os("PATH").ok_or(CliError::AuthorityGit)?;
    for directory in env::split_paths(&paths) {
        let candidate = directory.join(name);
        if is_executable(&candidate) {
            return candidate.canonicalize().map_err(|_| CliError::AuthorityGit);
        }
    }
    Err(CliError::AuthorityGit)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt as _;
    path.is_file()
        && path
            .metadata()
            .is_ok_and(|metadata| metadata.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

#[cfg(unix)]
pub(super) const fn null_config() -> &'static str {
    "/dev/null"
}

#[cfg(windows)]
pub(super) const fn null_config() -> &'static str {
    "NUL"
}

#[cfg(not(any(unix, windows)))]
pub(super) const fn null_config() -> &'static str {
    ""
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn fixed_git_environment_has_no_untrusted_config_or_pager() {
        let environment = fixed_environment("/safe".into());
        assert!(environment.contains(&("GIT_CONFIG_NOSYSTEM", "1".into())));
        assert!(environment.contains(&("GIT_CONFIG_GLOBAL", null_config().into())));
        assert!(environment.contains(&("GIT_PAGER", "cat".into())));
        assert_eq!(
            environment
                .iter()
                .find(|(key, _)| *key == "PATH")
                .map(|(_, value)| value),
            Some(&"/safe".into())
        );
    }
}
