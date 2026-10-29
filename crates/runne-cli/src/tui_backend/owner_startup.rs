//! Explicit owner consent before adopting the verified native installation.
use super::{BackendOwner, PathBuf, start_protected};
use serde::Deserialize;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    runtime_root: PathBuf,
    manifest: String,
    provider_profile: String,
    already_adopted: bool,
}

pub(super) async fn resolve(
    project: PathBuf,
    profile: Option<PathBuf>,
) -> Result<BackendOwner, String> {
    if profile.is_some() {
        return Err("Interactive tool sessions require the owned protected installation; custom external profiles remain available to non-interactive commands".into());
    }
    let project = project
        .canonicalize()
        .map_err(|_| "Project directory unavailable")?;
    if !project.is_dir() {
        return Err("Project must be a directory".into());
    }
    let executable = std::env::current_exe().map_err(|_| "CLI executable unavailable")?;
    let daemon = runne_platform_desktop::discover_bundled_runtime(&executable)
        .map_err(|_| "Colocated measured daemon unavailable")?;
    let mut preview = invoke(&daemon, &["terminal-adoption", "prepare"])?;
    if !preview.already_adopted {
        eprintln!("Runne will adopt the existing runtime for protected terminal sessions.");
        eprintln!(
            "History, credentials, provider budgets and current provider profile are preserved."
        );
        eprintln!("{}", consent_scope(&preview, &project));
        eprintln!(
            "The old external daemon must be stopped before adoption; no provider request is sent."
        );
        eprint!("Type ADOPT to authorize this exact installation transition: ");
        io::stderr()
            .flush()
            .map_err(|_| "Consent output unavailable")?;
        let mut response = String::new();
        io::stdin()
            .read_line(&mut response)
            .map_err(|_| "Consent input unavailable")?;
        if response.trim() != "ADOPT" {
            return Err("Installation adoption declined".into());
        }
        let committed = invoke(&daemon, &["terminal-adoption", "commit", &preview.manifest])?;
        if committed.manifest != preview.manifest
            || committed.runtime_root != preview.runtime_root
            || committed.provider_profile != preview.provider_profile
            || !committed.already_adopted
        {
            return Err("Adoption acknowledgement did not match consent".into());
        }
        preview = committed;
    }
    let root_handle = runne_platform_desktop::VerifiedRootHandle::open(&project)
        .map_err(|_| "Project root identity unavailable")?;
    let mut owner = start_protected(preview.runtime_root, project, None).await?;
    let workspace = owner
        .client
        .find_workspace_by_root(root_handle.filesystem_identity_digest())
        .await
        .map_err(|error| error.to_string())?;
    if let Some(workspace) = workspace {
        owner.bind_existing(workspace.id()).await?;
    }
    Ok(owner)
}

fn invoke(daemon: &Path, arguments: &[&str]) -> Result<Preview, String> {
    let measured = runne_api::ExecutableIdentityV1::measure(daemon)
        .map_err(|_| "Daemon measurement unavailable")?;
    let mut child = Command::new(daemon)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "Adoption command unavailable")?;
    let output = child
        .stdout
        .take()
        .ok_or("Adoption response pipe unavailable")?;
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
            .map_err(|_| "Adoption process unavailable")?
        {
            Some(status) => break status,
            None if std::time::Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(
                    "Adoption timed out; reconcile by retrying the exact transition".into(),
                );
            }
            None => std::thread::sleep(std::time::Duration::from_millis(20)),
        }
    };
    let bytes = receiver
        .recv_timeout(std::time::Duration::from_secs(1))
        .map_err(|_| "Adoption response timed out")?
        .map_err(|_| "Adoption response unreadable")?;
    let current = runne_api::ExecutableIdentityV1::measure(daemon)
        .map_err(|_| "Daemon measurement unavailable")?;
    if measured != current || !status.success() || bytes.len() > 16 * 1024 {
        return Err("Installation adoption unavailable: keep existing data and stop the old daemon before retrying the same transition".into());
    }
    let preview: Preview =
        serde_json::from_slice(&bytes).map_err(|_| "Adoption response invalid")?;
    if !preview.runtime_root.is_absolute()
        || preview.manifest.len() != 64
        || !preview.manifest.bytes().all(|b| b.is_ascii_hexdigit())
        || preview.provider_profile != "gocode-deepseek-responses-text/1"
    {
        return Err("Adoption response binding invalid".into());
    }
    Ok(preview)
}

fn sanitized(value: &str) -> String {
    value
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .collect()
}

fn consent_scope(preview: &Preview, project: &Path) -> String {
    format!(
        "Project: {}\nRuntime root: {}\nProvider profile: {}\nManifest: {}",
        sanitized(&project.display().to_string()),
        sanitized(&preview.runtime_root.display().to_string()),
        sanitized(&preview.provider_profile),
        sanitized(&preview.manifest)
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn adoption_consent_displays_exact_nonsecret_binding_without_terminal_controls() {
        let preview = Preview {
            runtime_root: "/runtime/\u{1b}[31mdata".into(),
            manifest: "a".repeat(64),
            provider_profile: "gocode-deepseek-responses-text/1".into(),
            already_adopted: false,
        };
        let text = consent_scope(&preview, Path::new("/project/\u{202e}source"));
        assert!(text.contains("Runtime root: /runtime/[31mdata"));
        assert!(text.contains(&preview.manifest));
        assert!(text.contains(&preview.provider_profile));
        assert!(!text.contains('\u{1b}') && !text.contains('\u{202e}'));
    }
}
