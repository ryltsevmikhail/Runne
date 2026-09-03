use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) struct LocalPackage {
    application: PathBuf,
    desktop: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PackageMode {
    CredentialWriter,
    CredentialService,
}

impl LocalPackage {
    pub(super) fn create(
        root: &Path,
        persistent_reference_probe: bool,
        mode: PackageMode,
    ) -> Result<Self, &'static str> {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .ok_or("repository-root")?;
        let application = root.join("Runne.app");
        let macos = application.join("Contents/MacOS");
        let contract =
            application.join("Contents/Resources/contracts/gocode-ui-client-2/bundle.json");
        fs::create_dir_all(&macos).map_err(|_| "package-macos")?;
        fs::create_dir_all(contract.parent().ok_or("package-contract-parent")?)
            .map_err(|_| "package-resources")?;
        let helpers = application.join("Contents/Library/Helpers");
        let service_bundle = helpers.join("RunneCredentialService.app");
        let service_macos = service_bundle.join("Contents/MacOS");
        for directory in [
            &application,
            &application.join("Contents"),
            &macos,
            &application.join("Contents/Resources"),
            &application.join("Contents/Resources/contracts"),
            &application.join("Contents/Resources/contracts/gocode-ui-client-2"),
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "package-directory-mode")?;
        }
        if mode == PackageMode::CredentialService {
            for directory in [
                &application.join("Contents/Library"),
                &helpers,
                &service_bundle,
                &service_bundle.join("Contents"),
                &service_macos,
            ] {
                fs::create_dir_all(directory).map_err(|_| "package-service-directory")?;
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                    .map_err(|_| "package-service-directory-mode")?;
            }
        }
        let desktop = macos.join("runne-desktop");
        let writer = macos.join("runne");
        let daemon = macos.join("runned");
        fs::copy(
            std::env::current_exe().map_err(|_| "desktop-source")?,
            &desktop,
        )
        .map_err(|_| "desktop-copy")?;
        fs::copy(
            build_runne(repository, persistent_reference_probe)?,
            &writer,
        )
        .map_err(|_| "writer-copy")?;
        fs::copy(
            build_runned(
                repository,
                persistent_reference_probe,
                mode == PackageMode::CredentialService,
            )?,
            &daemon,
        )
        .map_err(|_| "daemon-copy")?;
        fs::copy(
            repository.join("contracts/gocode-ui-client-2/bundle.json"),
            &contract,
        )
        .map_err(|_| "contract-copy")?;
        let service = service_macos.join("runne-credential-service");
        if mode == PackageMode::CredentialService {
            fs::copy(build_credential_service(repository)?, &service)
                .map_err(|_| "service-copy")?;
        }
        let mut executables = vec![
            (&desktop, "dev.runne.slice-e.desktop"),
            (&writer, "dev.runne.slice-e.writer"),
            (&daemon, "dev.runne.slice-e.daemon"),
        ];
        if mode == PackageMode::CredentialService {
            executables.push((&service, "dev.runne.slice-e.credential-service"));
        }
        for (path, identifier) in executables {
            command("/usr/bin/strip", &["-S", "-x"], path, "strip")?;
            let output = Command::new("/usr/bin/codesign")
                .args(["--force", "--keychain"])
                .arg(root.join("home/Library/Keychains/runne-ci.keychain-db"))
                .args([
                    "--sign",
                    super::keychain::LOCAL_SIGNING_IDENTITY,
                    "--timestamp=none",
                    "--identifier",
                ])
                .arg(identifier)
                .arg("--")
                .arg(path)
                .output()
                .map_err(|_| "codesign-command")?;
            if !output.status.success() {
                return Err("codesign-status");
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o500))
                .map_err(|_| "package-executable-mode")?;
        }
        fs::set_permissions(&contract, fs::Permissions::from_mode(0o400))
            .map_err(|_| "package-contract-mode")?;
        Ok(Self {
            application,
            desktop,
        })
    }

    pub(super) fn application(&self) -> &Path {
        &self.application
    }
    pub(super) fn desktop(&self) -> &Path {
        &self.desktop
    }

    pub(super) fn credential_service(&self) -> PathBuf {
        self.application.join(
            "Contents/Library/Helpers/RunneCredentialService.app/Contents/MacOS/runne-credential-service",
        )
    }
}

fn build_credential_service(repository: &Path) -> Result<PathBuf, &'static str> {
    let target = repository.join("target/slice-e-real-process-build");
    let output = Command::new("cargo")
        .args([
            "build",
            "--offline",
            "--locked",
            "-p",
            "runne-credential-service",
            "--features",
            "test-support",
        ])
        .current_dir(repository)
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST")
        .env_remove("RUNNE_CI_MACOS_KEYCHAIN")
        .output()
        .map_err(|_| "service-build-command")?;
    if !output.status.success() {
        return Err("service-build-status");
    }
    let binary = target.join("debug/runne-credential-service");
    binary
        .is_file()
        .then_some(binary)
        .ok_or("service-build-artifact")
}

fn build_runne(
    repository: &Path,
    persistent_reference_probe: bool,
) -> Result<PathBuf, &'static str> {
    let target = repository.join("target/slice-e-real-process-build");
    let features = if persistent_reference_probe {
        "local-native-enrollment-test,persistent-reference-probe"
    } else {
        "local-native-enrollment-test"
    };
    let output = Command::new("cargo")
        .args([
            "build",
            "--offline",
            "--locked",
            "-p",
            "runne-cli",
            "--bin",
            "runne",
            "--features",
            features,
        ])
        .current_dir(repository)
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST")
        .env_remove("RUNNE_CI_MACOS_KEYCHAIN")
        .output()
        .map_err(|_| "runne-build-command")?;
    if !output.status.success() {
        return Err("runne-build-status");
    }
    let binary = target.join("debug/runne");
    binary
        .is_file()
        .then_some(binary)
        .ok_or("runne-build-artifact")
}

fn build_runned(
    repository: &Path,
    persistent_reference_probe: bool,
    release: bool,
) -> Result<PathBuf, &'static str> {
    let target = repository.join("target/slice-e-real-process-build");
    let features = if persistent_reference_probe {
        "test-support,desktop-protected,persistent-reference-probe"
    } else {
        "test-support,desktop-protected"
    };
    let mut arguments = vec![
        "build",
        "--offline",
        "--locked",
        "-p",
        "runne-daemon",
        "--bin",
        "runned",
        "--features",
        features,
    ];
    if release {
        arguments.push("--release");
    }
    let output = Command::new("cargo")
        .args(arguments)
        .current_dir(repository)
        .env("CARGO_TARGET_DIR", &target)
        .env_remove("RUNNE_LOCAL_NATIVE_ENROLLMENT_TEST")
        .env_remove("RUNNE_CI_MACOS_KEYCHAIN")
        .output()
        .map_err(|_| "runned-build-command")?;
    if !output.status.success() {
        return Err("runned-build-status");
    }
    let binary = target.join(if release {
        "release/runned"
    } else {
        "debug/runned"
    });
    binary
        .is_file()
        .then_some(binary)
        .ok_or("runned-build-artifact")
}

fn command(
    program: &str,
    arguments: &[&str],
    path: &Path,
    error: &'static str,
) -> Result<(), &'static str> {
    Command::new(program)
        .args(arguments)
        .arg(path)
        .status()
        .map_err(|_| error)?
        .success()
        .then_some(())
        .ok_or(error)
}
