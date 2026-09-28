use runne_api::ProviderActivationBindingV1;
use std::ffi::OsString;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderSelection {
    binding: ProviderActivationBindingV1,
    explicit: bool,
}

impl ProviderSelection {
    pub fn binding(&self) -> ProviderActivationBindingV1 {
        self.binding.clone()
    }

    pub const fn is_explicit(&self) -> bool {
        self.explicit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderSelectionError;

impl std::fmt::Display for ProviderSelectionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("provider selection rejected")
    }
}

impl std::error::Error for ProviderSelectionError {}

pub fn provider_selection<I>(arguments: I) -> Result<ProviderSelection, ProviderSelectionError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut selected = None;
    for argument in arguments {
        let argument = argument.to_string_lossy();
        if !argument.starts_with("--provider") {
            continue;
        }
        if selected.is_some() {
            return Err(ProviderSelectionError);
        }
        selected = Some(match argument.as_ref() {
            "--provider=openai" => ProviderActivationBindingV1::openai_responses_text_v1(),
            "--provider=deepseek" => ProviderActivationBindingV1::deepseek_responses_text_v1(),
            _ => return Err(ProviderSelectionError),
        });
    }
    let explicit = selected.is_some();
    Ok(ProviderSelection {
        binding: selected.unwrap_or_else(ProviderActivationBindingV1::openai_responses_text_v1),
        explicit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(arguments: &[&str]) -> Result<ProviderSelection, ProviderSelectionError> {
        provider_selection(arguments.iter().map(OsString::from))
    }

    #[test]
    fn defaults_to_openai_and_accepts_exact_deepseek_selection() {
        let default = parse(&[]).unwrap();
        assert!(!default.is_explicit());
        assert_eq!(
            default.binding(),
            ProviderActivationBindingV1::openai_responses_text_v1()
        );
        let deepseek = parse(&["--provider=deepseek"]).unwrap();
        assert!(deepseek.is_explicit());
        assert_eq!(
            deepseek.binding(),
            ProviderActivationBindingV1::deepseek_responses_text_v1()
        );
        assert_eq!(
            parse(&["--provider=openai"]).unwrap().binding(),
            ProviderActivationBindingV1::openai_responses_text_v1()
        );
    }

    #[test]
    fn rejects_unknown_or_duplicate_provider_options() {
        for arguments in [
            vec!["--provider"],
            vec!["--provider=unknown"],
            vec!["--provider=deepseek", "--provider=deepseek"],
            vec!["--provider=openai", "--provider=deepseek"],
            vec!["--provider-other=deepseek"],
        ] {
            assert!(parse(&arguments).is_err(), "accepted {arguments:?}");
        }
    }

    #[test]
    fn unrelated_arguments_are_ignored() {
        assert!(provider_selection([OsString::from("--bundled-runtime")]).is_ok());
    }

    /// Stages a copy of the current test binary inside an owner-private
    /// directory, mirroring the daemon suite's `ControlledExecutable`
    /// precedent. The protected launch spec must only ever trust a directory
    /// chain the test fully controls: hosted CI workspaces carry a foreign
    /// owner uid and umask-dependent group-write bits under `target/`, which
    /// the production trusted-directory-chain checks correctly refuse to
    /// trust. The copy itself runs the unchanged `validate_executable_path`.
    fn stage_current_executable_owner_private() -> (tempfile::TempDir, std::path::PathBuf) {
        let root = owner_private_staging_directory();
        let staged = root.path().join("controlled-executable");
        std::fs::copy(
            std::env::current_exe().expect("current test executable"),
            &staged,
        )
        .expect("copy current executable into owner-private staging");
        set_owner_only_permissions(root.path());
        set_owner_only_permissions(&staged);
        (root, staged)
    }

    fn owner_private_staging_directory() -> tempfile::TempDir {
        let mut binding = tempfile::Builder::new();
        let builder = binding.prefix("provider-selection-spec-");
        #[cfg(unix)]
        {
            std::env::var_os("XDG_RUNTIME_DIR")
                .map(std::path::PathBuf::from)
                .filter(|path| path.is_absolute())
                .and_then(|directory| builder.tempdir_in(directory).ok())
                .unwrap_or_else(|| {
                    builder
                        .tempdir_in(std::path::PathBuf::from("/tmp"))
                        .expect("owner-private staging directory")
                })
        }
        #[cfg(not(unix))]
        builder.tempdir().expect("owner-private staging directory")
    }

    /// Explicit 0700 regardless of the ambient umask, like
    /// `tests/support/owner_private.rs::secure_directory`.
    fn set_owner_only_permissions(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
                .expect("owner-only permissions");
        }
        #[cfg(not(unix))]
        let _ = path;
    }

    #[test]
    fn selected_binding_is_carried_by_the_protected_launch_spec() {
        let temporary = tempfile::tempdir().unwrap();
        let (_staging, executable) = stage_current_executable_owner_private();
        let selection = parse(&["--provider=deepseek"]).unwrap();
        let spec = runne_platform_desktop::ProtectedBundledRuntimeLaunchSpec::new(
            &executable,
            temporary.path(),
        )
        .unwrap()
        .with_provider_activation(selection.binding());
        assert_eq!(
            spec.provider_activation(),
            Some(&ProviderActivationBindingV1::deepseek_responses_text_v1())
        );
    }
}
