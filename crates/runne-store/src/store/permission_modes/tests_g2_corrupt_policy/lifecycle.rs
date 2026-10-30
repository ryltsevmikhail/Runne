use super::fixture::Fixture;
use std::os::unix::fs::MetadataExt;

// Keeps TempDir disposal after every fixture handle even during unwinding.
pub(super) struct OwnedFixture(Option<Fixture>);
impl OwnedFixture {
    pub(super) fn new() -> Self {
        Self::with_fence(|fence| fence)
    }

    pub(super) fn with_fence(
        decorate: impl FnOnce(
            std::sync::Arc<dyn crate::store::taskrun_local_command::PermissionRootFenceOwnerV1>,
        ) -> std::sync::Arc<dyn crate::store::taskrun_local_command::PermissionRootFenceOwnerV1>,
    ) -> Self {
        let mount = std::path::Path::new("/dev/shm");
        assert_eq!(std::fs::canonicalize(mount).unwrap(), mount);
        let mounts = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
        let entries: Vec<_> = mounts
            .lines()
            .filter(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                fields.get(4) == Some(&"/dev/shm")
            })
            .collect();
        assert_eq!(entries.len(), 1, "NOTRUN: unambiguous guest RAM mount");
        let (_, filesystem) = entries[0].split_once(" - ").unwrap();
        assert_eq!(filesystem.split_whitespace().next(), Some("tmpfs"));
        let root = tempfile::Builder::new()
            .prefix("g2-corrupt-policy-")
            .tempdir_in(mount)
            .unwrap();
        assert_eq!(
            std::fs::metadata(root.path()).unwrap().dev(),
            std::fs::metadata(mount).unwrap().dev()
        );
        Self(Some(Fixture::with_root_and_fence(root, decorate)))
    }
    pub(super) fn get(&self) -> &Fixture {
        self.0.as_ref().unwrap()
    }
}
impl Drop for OwnedFixture {
    fn drop(&mut self) {
        if let Some(f) = self.0.take() {
            let Fixture {
                root,
                store,
                trust,
                native,
                held,
                scope,
                principal,
                launch,
                project: _,
            } = f;
            drop((store, trust, native, held, scope, principal, launch));
            let result = root.close();
            if std::thread::panicking() {
                eprintln!("G2_FAILURE_ROOT_DISPOSAL {result:?}");
            } else {
                result.expect("owned RAM disposal after fixture handles closed");
            }
        }
    }
}
