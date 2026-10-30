//! Measured one-shot calls into the colocated daemon command surface.
use serde::de::DeserializeOwned;
use std::io::Read as _;
use std::path::Path;
use std::process::{Command, Stdio};

/// Runs one non-interactive daemon command and decodes its bounded JSON reply.
///
/// The daemon image is measured before and after the call so a reply from a
/// replaced executable is never accepted as installation evidence.
pub(super) fn invoke<T: DeserializeOwned>(daemon: &Path, arguments: &[&str]) -> Result<T, String> {
    let measured = runne_api::ExecutableIdentityV1::measure(daemon)
        .map_err(|_| "Daemon measurement unavailable")?;
    let mut child = Command::new(daemon)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Installation command unavailable")?;
    let output = child
        .stdout
        .take()
        .ok_or("Installation response pipe unavailable")?;
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = output
            .take(16 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes);
        let _ = sender.send(result);
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let status = loop {
        match child
            .try_wait()
            .map_err(|_| "Installation process unavailable")?
        {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("Installation command timed out; retry the same transition".into());
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    let bytes = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .map_err(|_| "Installation response timed out")?
        .map_err(|_| "Installation response unreadable")?;
    let current = runne_api::ExecutableIdentityV1::measure(daemon)
        .map_err(|_| "Daemon measurement unavailable")?;
    if measured != current || !status.success() || bytes.len() > 16 * 1024 {
        return Err(
            "Installation command unavailable: keep existing data and retry the same transition"
                .into(),
        );
    }
    serde_json::from_slice(&bytes).map_err(|_| "Installation response invalid".into())
}
