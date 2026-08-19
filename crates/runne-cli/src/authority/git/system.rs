//! Hardened process runner for read-only Git object commands.

use std::io::{Read as _, Write as _};
use std::path::Path;
use std::process::{Command, Stdio};

use super::super::super::CliError;
use super::MAX_GIT_OUTPUT_BYTES;
use super::system_config;

pub struct SystemGit;

pub trait GitCommandRunner {
    fn run(&self, root: &Path, arguments: &[String], input: &[u8]) -> Result<GitOutput, CliError>;
}

pub struct GitOutput {
    pub(super) stdout: Vec<u8>,
    pub(super) status: i32,
}

impl GitCommandRunner for SystemGit {
    fn run(&self, root: &Path, arguments: &[String], input: &[u8]) -> Result<GitOutput, CliError> {
        let configuration = system_config::discover()?;
        let mut command = Command::new(configuration.executable);
        command
            .current_dir(root)
            .env_clear()
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.untrackedCache=false",
            ])
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        for (key, value) in system_config::fixed_environment(configuration.path) {
            command.env(key, value);
        }
        let mut child = command.spawn().map_err(|_| CliError::AuthorityGit)?;
        child
            .stdin
            .take()
            .ok_or(CliError::AuthorityGit)?
            .write_all(input)
            .map_err(|_| CliError::AuthorityGit)?;
        let stdout = child.stdout.take().ok_or(CliError::AuthorityGit)?;
        let mut bytes = Vec::with_capacity(4096);
        stdout
            .take((MAX_GIT_OUTPUT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| CliError::AuthorityGit)?;
        if bytes.len() > MAX_GIT_OUTPUT_BYTES {
            let _ = child.kill();
            let _ = child.wait();
            return Err(CliError::AuthorityGit);
        }
        let status = child.wait().map_err(|_| CliError::AuthorityGit)?;
        Ok(GitOutput {
            stdout: bytes,
            status: status.code().unwrap_or(-1),
        })
    }
}
