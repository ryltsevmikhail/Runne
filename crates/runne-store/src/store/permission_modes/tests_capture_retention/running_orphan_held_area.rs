//! Diagnostic correlation composed with the public held-area authority.
//! Callers retain the real unreaped PermissionChild; observations cannot replace it.
use super::area_path::{self, AreaPath};
use super::association::{self, Association, Spawner};
use super::context::CaseContext;
use super::io::bounded;
use runne_platform::process_managed_area::{
    LinuxManagedArea, LinuxManagedAreaRoot, ManagedAreaBinding, ManagedAreaIdentity,
};
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

fn join(file: &File, path: &Path, device: u64, inode: u64) {
    for metadata in [
        file.metadata().unwrap(),
        std::fs::symlink_metadata(path).unwrap(),
    ] {
        assert!(metadata.is_dir());
        assert_eq!((metadata.dev(), metadata.ino()), (device, inode));
    }
    assert_eq!(std::fs::canonicalize(path).unwrap(), path);
}

fn directory(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .unwrap()
}

fn singleton(text: &str, expected: u32) {
    let values: Vec<_> = text.split_ascii_whitespace().collect();
    assert_eq!(
        values,
        [expected.to_string()],
        "exact no-fork workload member"
    );
}

pub(super) struct HeldAreaReader {
    path: AreaPath,
    root_directory: File,
    area_directory: File,
    area: LinuxManagedArea,
}

impl HeldAreaReader {
    pub(super) fn reopen(
        context: &CaseContext,
        root: &LinuxManagedAreaRoot,
        original: &ManagedAreaIdentity,
        binding: ManagedAreaBinding,
    ) -> Self {
        context.check_roots();
        let current = bounded(Path::new("/proc/self/cgroup"), 4096, context.deadline);
        assert_eq!(association::membership(&current), context.record.membership);
        let mounts = bounded(Path::new("/proc/self/mountinfo"), 65536, context.deadline);
        let path = area_path::locate(original, &current, &mounts);
        // Public reopen performs boot/root/binding/area verification. Path joins
        // below add diagnostics; they do not mint a replacement authority.
        let area = root.reopen_area(original.clone(), binding).unwrap();
        assert_eq!(area.identity().to_bytes(), original.to_bytes());
        let root_directory = directory(&path.root);
        let area_directory = directory(&path.directory);
        let value = Self {
            path,
            root_directory,
            area_directory,
            area,
        };
        value.check(context);
        value
    }

    pub(super) fn check(&self, context: &CaseContext) {
        context.deadline.check();
        join(
            &self.root_directory,
            &self.path.root,
            self.path.root_device,
            self.path.root_inode,
        );
        join(
            &self.area_directory,
            &self.path.directory,
            self.path.area_device,
            self.path.area_inode,
        );
        // Public API additionally checks held/current name and cgroup2 type.
        let _population = self.area.is_populated().unwrap();
        context.deadline.check();
    }

    pub(super) fn live_association(
        &self,
        context: &CaseContext,
        spawner: &Spawner,
        native: u32,
        outer_pids: &[u32],
    ) -> Association {
        self.check(context);
        assert!(self.area.is_populated().unwrap());
        let members = self.path.directory.join("cgroup.procs");
        singleton(&bounded(&members, 4096, context.deadline), native);
        let observed = association::observe(
            spawner,
            native,
            &self.path.membership,
            outer_pids,
            context.observer_deadline(),
        );
        context.deadline.check();
        singleton(&bounded(&members, 4096, context.deadline), native);
        assert!(self.area.is_populated().unwrap());
        self.check(context);
        observed
    }

    pub(super) fn area(&self) -> &LinuxManagedArea {
        &self.area
    }

    pub(super) fn into_area(self, context: &CaseContext) -> LinuxManagedArea {
        self.check(context);
        self.area
    }
}

#[cfg(test)]
mod tests {
    use super::singleton;

    #[test]
    fn membership_is_exact_singleton_not_presence() {
        singleton("42\n", 42);
        for text in ["", "42\n43\n", "43\n", "042\n", "42 42\n", "-42\n"] {
            assert!(std::panic::catch_unwind(|| singleton(text, 42)).is_err());
        }
    }
}
