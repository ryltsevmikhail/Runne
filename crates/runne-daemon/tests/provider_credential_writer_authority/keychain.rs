use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::Command;

pub(super) const LOCAL_SIGNING_IDENTITY: &str = "Runne Slice E Local Code Signing";
pub(super) const KEYCHAIN_PASSWORD: &str = "slice-e-disposable";
const IDENTITY_PASSWORD: &str = "slice-e-identity";

pub(super) struct DisposableKeychain {
    temporary: Option<tempfile::TempDir>,
    root: PathBuf,
    home: PathBuf,
    path: PathBuf,
    created: bool,
}

/// Common tempfile prefix for every scenario fixture root. The harness
/// process guards match this prefix (with a leading path separator), so the
/// two sites must stay in sync through this constant.
pub(crate) const FIXTURE_TEMPFILE_PREFIX: &str = "runne-slice-e-";

impl DisposableKeychain {
    pub(super) fn create() -> Result<Self, &'static str> {
        let temporary = tempfile::Builder::new()
            .prefix(FIXTURE_TEMPFILE_PREFIX)
            .tempdir()
            .map_err(|_| "temporary-root")?;
        let root = fs::canonicalize(temporary.path()).map_err(|_| "temporary-canonical")?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|_| "temporary-permissions")?;
        let home = root.join("home");
        let keychains = home.join("Library/Keychains");
        fs::create_dir_all(&keychains).map_err(|_| "keychain-directory")?;
        for directory in [&home, &home.join("Library"), &keychains] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| "keychain-directory-permissions")?;
        }
        let path = keychains.join("runne-ci.keychain-db");
        let mut fixture = Self {
            temporary: Some(temporary),
            root,
            home,
            path,
            created: false,
        };
        fixture.validate_target(false)?;
        fixture.security(&["create-keychain", "-p", KEYCHAIN_PASSWORD], true)?;
        fixture.created = true;
        fs::set_permissions(&fixture.path, fs::Permissions::from_mode(0o600))
            .map_err(|_| "keychain-file-permissions")?;
        fixture.validate_target(true)?;
        fixture.security(&["set-keychain-settings", "-lut", "21600"], false)?;
        fixture.security(&["unlock-keychain", "-p", KEYCHAIN_PASSWORD], false)?;
        fixture.create_signing_identity()?;
        Ok(fixture)
    }

    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn home(&self) -> &Path {
        &self.home
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    pub(super) fn cleanup(mut self) -> Result<(), &'static str> {
        self.cleanup_inner()?;
        self.temporary.take();
        Ok(())
    }

    fn security(&self, arguments: &[&str], append_path: bool) -> Result<(), &'static str> {
        let mut command = Command::new("/usr/bin/security");
        command.args(arguments);
        if append_path || arguments.first() != Some(&"create-keychain") {
            command.arg(&self.path);
        }
        let output = command.output().map_err(|_| "security-command")?;
        output
            .status
            .success()
            .then_some(())
            .ok_or("security-status")
    }

    fn create_signing_identity(&self) -> Result<(), &'static str> {
        let configuration = self.root.join("slice-e-openssl.cnf");
        let private_key = self.root.join("slice-e-signing-key.pem");
        let certificate = self.root.join("slice-e-signing-cert.pem");
        let identity = self.root.join("slice-e-signing-identity.p12");
        fs::write(
            &configuration,
            "[req]\ndistinguished_name=dn\nx509_extensions=extensions\nprompt=no\n[dn]\nCN=Runne Slice E Local Code Signing\n[extensions]\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=codeSigning\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n",
        )
        .map_err(|_| "signing-configuration")?;
        command(
            "/usr/bin/openssl",
            &[
                "req", "-new", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                "-config",
            ],
            &[&configuration, &private_key, &certificate],
            "signing-certificate",
        )?;
        let output = Command::new("/usr/bin/openssl")
            .args(["pkcs12", "-export", "-inkey"])
            .arg(&private_key)
            .arg("-in")
            .arg(&certificate)
            .arg("-out")
            .arg(&identity)
            .arg("-passout")
            .arg(format!("pass:{IDENTITY_PASSWORD}"))
            .output()
            .map_err(|_| "signing-identity-command")?;
        if !output.status.success() {
            return Err("signing-identity-status");
        }
        let imported = Command::new("/usr/bin/security")
            .arg("import")
            .arg(&identity)
            .arg("-k")
            .arg(&self.path)
            .args(["-P", IDENTITY_PASSWORD, "-T", "/usr/bin/codesign"])
            .output()
            .map_err(|_| "signing-import-command")?;
        if !imported.status.success() {
            return Err("signing-import-status");
        }
        self.security(
            &[
                "set-key-partition-list",
                "-S",
                "apple-tool:,apple:",
                "-s",
                "-k",
                KEYCHAIN_PASSWORD,
            ],
            false,
        )
    }

    fn validate_target(&self, must_exist: bool) -> Result<(), &'static str> {
        let expected = self
            .root
            .join("home/Library/Keychains/runne-ci.keychain-db");
        if self.path != expected || !self.root.is_absolute() {
            return Err("unsafe-keychain-target");
        }
        let root = fs::canonicalize(&self.root).map_err(|_| "keychain-root")?;
        if must_exist {
            let metadata = fs::symlink_metadata(&self.path).map_err(|_| "keychain-missing")?;
            let path = fs::canonicalize(&self.path).map_err(|_| "keychain-canonical")?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode().trailing_zeros() < 6
                || !path.starts_with(root)
            {
                return Err("unsafe-keychain-target");
            }
        } else if self.path.exists() {
            return Err("keychain-preexists");
        }
        Ok(())
    }

    fn cleanup_inner(&mut self) -> Result<(), &'static str> {
        if !self.created {
            return Ok(());
        }
        self.validate_target(true)?;
        self.security(&["delete-keychain"], false)?;
        self.created = false;
        (!self.path.exists()).then_some(()).ok_or("keychain-delete")
    }
}

fn command(
    program: &str,
    prefix: &[&str],
    paths: &[&Path],
    error: &'static str,
) -> Result<(), &'static str> {
    let mut command = Command::new(program);
    command.args(prefix).arg(paths[0]);
    command.arg("-keyout").arg(paths[1]);
    command.arg("-out").arg(paths[2]);
    command
        .output()
        .map_err(|_| error)?
        .status
        .success()
        .then_some(())
        .ok_or(error)
}

impl Drop for DisposableKeychain {
    fn drop(&mut self) {
        let _ = self.cleanup_inner();
    }
}
