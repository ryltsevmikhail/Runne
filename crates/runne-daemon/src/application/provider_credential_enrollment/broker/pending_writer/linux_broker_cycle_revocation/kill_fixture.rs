use std::path::PathBuf;

const FIXTURE_ENV: &str = "RUNNE_D1_1B_POST_DELETE_KILL_FIXTURE_ROOT";

pub(super) struct PostDeleteKillFixture {
    directory: tempfile::TempDir,
    previous: Option<std::ffi::OsString>,
}

impl PostDeleteKillFixture {
    pub(super) fn new() -> Self {
        let runtime = std::env::var_os("XDG_RUNTIME_DIR")
            .expect("private XDG runtime directory required for fixture propagation");
        let directory = tempfile::Builder::new()
            .prefix("runne-d1-1b-kill-")
            .tempdir_in(runtime)
            .unwrap();
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = directory.path().canonicalize().unwrap();
        let previous = std::env::var_os(FIXTURE_ENV);
        // This ignored owner-session test needs the production test hook in
        // the child CLI environment; the per-run private path scopes it.
        unsafe { std::env::set_var(FIXTURE_ENV, &root) };
        Self {
            directory,
            previous,
        }
    }

    pub(super) fn root(&self) -> PathBuf {
        self.directory.path().to_owned()
    }
}

impl Drop for PostDeleteKillFixture {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            unsafe { std::env::set_var(FIXTURE_ENV, previous) };
        } else {
            unsafe { std::env::remove_var(FIXTURE_ENV) };
        }
    }
}
