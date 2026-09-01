use std::fs;
use std::io::Read as _;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use sha2::{Digest as _, Sha256};

const FAKE_AD_HOC_TEAM: &str = "RUNNE12345";
static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub enum SigningMode<'a> {
    AdHoc,
    DeveloperId(&'a str),
}

pub struct TestPackage {
    root: PathBuf,
    view: PackageView,
}

pub struct PackageView {
    application: PathBuf,
}

pub struct CodeIdentity {
    pub identifier: String,
    pub team_identifier: String,
    pub cdhash: String,
}

#[derive(Clone, Copy)]
pub enum PackageRole {
    Desktop,
    Writer,
    Daemon,
    Contract,
}

impl TestPackage {
    pub fn new(signing: SigningMode<'_>) -> Self {
        let temporary =
            fs::canonicalize(std::env::temp_dir()).expect("canonical test temporary directory");
        let root = temporary.join(format!(
            "runne-b2b3i-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let application = root.join("Runne.app");
        let view = PackageView { application };
        create_layout(&view);
        sign_helpers(&view, signing);
        Self { root, view }
    }

    pub const fn view(&self) -> &PackageView {
        &self.view
    }
}

impl PackageView {
    pub fn from_current_executable() -> Self {
        let executable = fs::canonicalize(std::env::current_exe().expect("current executable"))
            .expect("canonical current executable");
        let macos = executable.parent().expect("MacOS directory");
        let contents = macos.parent().expect("Contents directory");
        let application = contents.parent().expect("Runne.app").to_path_buf();
        assert_eq!(
            application.file_name().and_then(|name| name.to_str()),
            Some("Runne.app")
        );
        Self { application }
    }

    pub fn desktop(&self) -> PathBuf {
        self.application.join("Contents/MacOS/runne-desktop")
    }

    pub fn writer(&self) -> PathBuf {
        self.application.join("Contents/MacOS/runne")
    }

    pub fn daemon(&self) -> PathBuf {
        self.application.join("Contents/MacOS/runned")
    }

    pub fn contract(&self) -> PathBuf {
        self.application
            .join("Contents/Resources/contracts/gocode-ui-client-2/bundle.json")
    }

    pub fn digest(&self, role: PackageRole) -> [u8; 32] {
        let path = self.path(role);
        let mut file = fs::File::open(&path).expect("open package role");
        let mut hasher = Sha256::new();
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            let read = file.read(&mut chunk).expect("read package role");
            if read == 0 {
                break;
            }
            hasher.update(&chunk[..read]);
        }
        hasher.finalize().into()
    }

    pub fn code_identity(&self, role: PackageRole) -> CodeIdentity {
        assert!(!matches!(role, PackageRole::Contract));
        let output = Command::new("/usr/bin/codesign")
            .args(["-dv", "--verbose=4"])
            .arg(self.path(role))
            .output()
            .expect("inspect signed helper");
        assert!(output.status.success(), "codesign inspection failed");
        let details = String::from_utf8(output.stderr).expect("codesign UTF-8 output");
        let team = exact_detail(&details, "TeamIdentifier=");
        CodeIdentity {
            identifier: exact_detail(&details, "Identifier="),
            team_identifier: if team == "not set" {
                FAKE_AD_HOC_TEAM.to_owned()
            } else {
                team
            },
            cdhash: exact_detail(&details, "CDHash=").to_ascii_lowercase(),
        }
    }

    fn path(&self, role: PackageRole) -> PathBuf {
        match role {
            PackageRole::Desktop => self.desktop(),
            PackageRole::Writer => self.writer(),
            PackageRole::Daemon => self.daemon(),
            PackageRole::Contract => self.contract(),
        }
    }
}

fn create_layout(package: &PackageView) {
    let macos = package.application.join("Contents/MacOS");
    let contract = package
        .application
        .join("Contents/Resources/contracts/gocode-ui-client-2");
    fs::create_dir_all(&macos).expect("create MacOS directory");
    fs::create_dir_all(&contract).expect("create contract directory");
    fs::set_permissions(&macos, fs::Permissions::from_mode(0o755))
        .expect("secure MacOS directory mode");
    let mut current = Some(contract.as_path());
    while let Some(directory) = current {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
            .expect("secure package directory mode");
        if directory == package.application {
            break;
        }
        current = directory.parent();
    }
    let bundle = package.contract();
    fs::write(&bundle, b"{\"schema\":\"gocode-ui-client-2\"}").expect("write contract");
    fs::set_permissions(bundle, fs::Permissions::from_mode(0o644)).expect("secure contract mode");
}

fn sign_helpers(package: &PackageView, signing: SigningMode<'_>) {
    let current = std::env::current_exe().expect("current test executable");
    for (path, identifier) in [
        (package.desktop(), "dev.runne.desktop"),
        (package.writer(), "dev.runne.writer"),
        (package.daemon(), "dev.runne.daemon"),
    ] {
        fs::copy(&current, &path).expect("copy helper binary");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))
            .expect("secure executable mode");
        let mut command = Command::new("/usr/bin/codesign");
        command.args(["--force", "--sign"]);
        match signing {
            SigningMode::AdHoc => {
                command.arg("-");
            }
            SigningMode::DeveloperId(identity) => {
                command
                    .arg(identity)
                    .args(["--timestamp=none", "--options", "runtime"]);
            }
        }
        let status = command
            .args(["--identifier", identifier])
            .arg(&path)
            .status()
            .expect("codesign helper");
        assert!(status.success(), "codesign failed for {identifier}");
    }
}

fn exact_detail(output: &str, prefix: &str) -> String {
    let mut values = output.lines().filter_map(|line| line.strip_prefix(prefix));
    let value = values.next().expect("codesign detail is present");
    assert!(
        values.next().is_none(),
        "duplicate codesign detail: {prefix}"
    );
    value.to_owned()
}

impl Drop for TestPackage {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove scoped test package");
    }
}
