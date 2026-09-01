#![cfg(test)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

pub(super) struct PackageFixture {
    container: PathBuf,
    application: PathBuf,
}

impl PackageFixture {
    pub(super) fn new() -> Self {
        let temporary = std::env::temp_dir();
        let temporary = temporary.strip_prefix("/var").map_or_else(
            |_| temporary.clone(),
            |suffix| Path::new("/private/var").join(suffix),
        );
        let container = temporary.join(format!(
            "runne-b2b2ii-package-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&container).expect("create unique package fixture");
        let application = container.join("Runne.app");
        Self::populate(&application);
        Self {
            container,
            application,
        }
    }

    pub(super) fn application(&self) -> &Path {
        &self.application
    }

    pub(super) fn role(&self, name: &str) -> PathBuf {
        match name {
            "contract" => self
                .application
                .join("Contents/Resources/contracts/gocode-ui-client-2/bundle.json"),
            name => self.application.join("Contents/MacOS").join(name),
        }
    }

    pub(super) fn replace_application(&self) {
        let retained = self.container.join("retained.app");
        fs::rename(&self.application, retained).expect("move original application");
        Self::populate(&self.application);
    }

    fn populate(application: &Path) {
        let contents = application.join("Contents");
        let macos = contents.join("MacOS");
        let resources = contents.join("Resources");
        let contracts = resources.join("contracts");
        let bundle = contracts.join("gocode-ui-client-2");
        fs::create_dir_all(&macos).expect("create executable directory");
        fs::create_dir_all(&bundle).expect("create contract directory");
        for directory in [
            application,
            &contents,
            &macos,
            &resources,
            &contracts,
            &bundle,
        ] {
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755))
                .expect("secure fixture directory");
        }
        for (name, bytes) in [
            ("runne-desktop", b"desktop-v1".as_slice()),
            ("runne", b"writer-v1".as_slice()),
            ("runned", b"daemon-v1".as_slice()),
        ] {
            let path = macos.join(name);
            fs::write(&path, bytes).expect("write executable role");
            fs::set_permissions(path, fs::Permissions::from_mode(0o755))
                .expect("secure executable role");
        }
        let contract = bundle.join("bundle.json");
        fs::write(&contract, b"contract-v1").expect("write contract role");
        fs::set_permissions(contract, fs::Permissions::from_mode(0o644))
            .expect("secure contract role");
    }
}

impl Drop for PackageFixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.container).expect("remove scoped package fixture");
    }
}
