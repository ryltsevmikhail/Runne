use crate::ProcessOutcome;
use std::ffi::OsString;
use std::os::unix::{fs::MetadataExt, process::CommandExt};

pub(super) fn selected(arguments: &[OsString]) -> bool {
    arguments.iter().map(|value| value.to_str()).eq([
        Some("provider"),
        Some("credential"),
        Some("login"),
        Some("deepseek"),
    ])
}

pub(super) fn run() -> ProcessOutcome {
    let result = (|| {
        let cli = std::env::current_exe()?.canonicalize()?;
        let daemon = cli
            .parent()
            .ok_or_else(|| std::io::Error::other("missing package"))?
            .join("runne-credential-host");
        let metadata = std::fs::symlink_metadata(&daemon)?;
        if !metadata.is_file()
            || metadata.uid() != std::fs::metadata(&cli)?.uid()
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o100 == 0
        {
            return Err(std::io::Error::other("invalid package"));
        }
        let mut command = std::process::Command::new(&daemon);
        command.env_clear().env("PATH", "/usr/bin:/bin");
        for name in [
            "HOME",
            "USER",
            "LANG",
            "TERM",
            "XDG_CONFIG_HOME",
            "XDG_DATA_HOME",
            "XDG_STATE_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "DISPLAY",
            "WAYLAND_DISPLAY",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        command.args(["deepseek", "pair"]);
        Err::<(), _>(command.exec())
    })();
    let _ = result;
    ProcessOutcome {
        stdout: String::new(),
        stderr: "cannot launch packaged Linux credential host\n".into(),
        exit_code: 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn status_uses_authenticated_readiness_without_legacy_keyring_probe() {
        for (readiness, expected) in [
            (runne_api::ProviderReadinessStatusV1::Ready, "readiness: ready"),
            (runne_api::ProviderReadinessStatusV1::CredentialMissing, "readiness: credential_missing"),
            (runne_api::ProviderReadinessStatusV1::SecureStoreUnavailable, "readiness: secure_store_unavailable"),
        ] {
            let status = runne_api::ProviderStatusSnapshotV1::new("deepseek", "deepseek_responses_text_v1", "gocode-deepseek-responses-text/1", [1;32], readiness, true).unwrap();
            let output = crate::format_authenticated_provider_statuses(&[status]).unwrap();
            assert!(output.contains(expected));
            assert!(output.contains("source: authenticated runtime"));
        }
        assert!(crate::format_authenticated_provider_statuses(&[]).is_none());
    }

    #[test]
    fn only_exact_deepseek_login_selects_the_local_host() {
        let args = |values: &[&str]| values.iter().map(OsString::from).collect::<Vec<_>>();
        assert!(selected(&args(&[
            "provider",
            "credential",
            "login",
            "deepseek"
        ])));
        for invalid in [
            vec!["provider", "credential", "login", "openai"],
            vec!["provider", "credential", "login", "deepseek", "secret"],
            vec!["provider", "credential", "set", "--provider", "deepseek"],
        ] {
            assert!(!selected(&args(&invalid)));
        }
    }
}
