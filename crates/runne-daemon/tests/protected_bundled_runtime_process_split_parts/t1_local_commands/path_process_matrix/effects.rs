use std::os::unix::fs::MetadataExt as _;

use super::{
    CHILD_ARGUMENT_WITH_QUOTES, CHILD_ARGUMENT_WITH_SPACES, CHILD_ENV_VALUE, CROSS_VOLUME_SEED,
    PathProcessMatrix,
};

impl PathProcessMatrix {
    pub(in crate::t1_local_commands::permission_modes) fn assert_pending(&self) {
        self.assert_python_script_unchanged();
        assert_eq!(
            std::fs::read_to_string(&self.symlink_target).unwrap(),
            "symlink-seed\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.hardlink_source).unwrap(),
            "hardlink-seed\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.rename_source).unwrap(),
            "rename-source\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.replace_source).unwrap(),
            "replacement-new\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.replace_target).unwrap(),
            "replacement-old\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.cross_volume_source).unwrap(),
            CROSS_VOLUME_SEED
        );
        assert_eq!(
            std::fs::read_to_string(&self.hidden_device_source).unwrap(),
            CROSS_VOLUME_SEED,
            "host-side /dev/shm canary stays unchanged while hidden from the child"
        );
        assert!(self.sibling.is_dir());
        assert!(self.fixture_cwd.is_dir());
        assert!(self.hidden_device_directory.path().starts_with("/dev/shm"));
        for path in [
            &self.symlink_in_workspace,
            &self.hardlink_in_sibling,
            &self.rename_target,
            &self.case_upper,
            &self.case_lower,
            &self.case_log,
            &self.child_marker,
            &self.python_stderr,
            &self.cross_volume_output,
            &self.cross_volume_link_target,
            &self.cross_volume_rename_target,
        ] {
            assert!(!path.exists(), "pending command already created {path:?}");
        }
    }

    pub(in crate::t1_local_commands::permission_modes) fn assert_effects(&self) {
        let python_stderr = std::fs::read_to_string(&self.python_stderr)
            .expect("read path-process child stderr captured in fixture cwd");
        eprintln!("INFO: path-process child stderr: {python_stderr:?}");
        assert!(
            python_stderr.is_empty(),
            "path-process child wrote stderr, including any Python traceback:\n{python_stderr}"
        );
        self.assert_python_script_unchanged();
        assert!(
            std::fs::symlink_metadata(&self.symlink_in_workspace)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(&self.symlink_in_workspace).unwrap(),
            self.symlink_target
        );
        assert_eq!(
            std::fs::read_to_string(&self.symlink_target).unwrap(),
            "symlink-seed\nsymlink-followed\n"
        );

        let hardlink_source = std::fs::metadata(&self.hardlink_source).unwrap();
        let hardlink_alias = std::fs::metadata(&self.hardlink_in_sibling).unwrap();
        assert_eq!(
            (hardlink_source.dev(), hardlink_source.ino()),
            (hardlink_alias.dev(), hardlink_alias.ino()),
            "workspace and sibling paths retain one hardlinked inode"
        );
        assert_eq!(
            std::fs::read_to_string(&self.hardlink_source).unwrap(),
            "hardlink-seed\nhardlink-followed\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.rename_target).unwrap(),
            "rename-source\n"
        );
        assert!(!self.rename_source.exists());
        assert_eq!(
            std::fs::read_to_string(&self.replace_target).unwrap(),
            "replacement-new\n"
        );
        assert!(!self.replace_source.exists());

        let upper = std::fs::metadata(&self.case_upper).unwrap();
        let lower = std::fs::metadata(&self.case_lower).unwrap();
        let case_sensitive = (upper.dev(), upper.ino()) != (lower.dev(), lower.ino());
        let workspace_device = std::fs::metadata(&self.workspace).unwrap().dev();
        let cross_volume_device = std::fs::metadata(&self.cross_volume_source).unwrap().dev();
        let hidden_device = std::fs::metadata(&self.hidden_device_source).unwrap().dev();
        eprintln!(
            "INFO: path-process filesystem probe: case_sensitive={case_sensitive} workspace_st_dev={workspace_device} worktree_cross_volume_st_dev={cross_volume_device} host_dev_shm_canary_st_dev={hidden_device}"
        );
        assert_eq!(
            std::fs::read_to_string(&self.case_log).unwrap(),
            format!("case_sensitive={case_sensitive}\n"),
            "case log records the result measured on this filesystem"
        );
        if case_sensitive {
            assert_eq!(
                std::fs::read_to_string(&self.case_upper).unwrap(),
                "upper\n"
            );
            assert_eq!(
                std::fs::read_to_string(&self.case_lower).unwrap(),
                "lower\n"
            );
        } else {
            assert_eq!(
                std::fs::read_to_string(&self.case_upper).unwrap(),
                "lower\n"
            );
            assert_eq!(
                std::fs::read_to_string(&self.case_lower).unwrap(),
                "lower\n"
            );
        }

        let cwd_name = self
            .fixture_cwd
            .file_name()
            .expect("fixture cwd has a name")
            .to_string_lossy();
        let expected_marker = format!(
            "argv0={CHILD_ARGUMENT_WITH_SPACES};argv1={CHILD_ARGUMENT_WITH_QUOTES};env={CHILD_ENV_VALUE};cwd={cwd_name}\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.child_marker).unwrap(),
            expected_marker,
            "one child appended the exact structured argv, fixture environment, and cwd marker"
        );

        assert_eq!(
            std::fs::read_to_string(&self.cross_volume_source).unwrap(),
            CROSS_VOLUME_SEED,
            "cross-volume rename failure preserves its source"
        );
        assert_eq!(
            std::fs::read_to_string(&self.hidden_device_source).unwrap(),
            CROSS_VOLUME_SEED,
            "host-side /dev/shm canary remains unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(&self.cross_volume_output).unwrap(),
            "cross-volume-output:cross-volume-input\n"
        );
        assert!(!self.cross_volume_link_target.exists());
        assert!(!self.cross_volume_rename_target.exists());
        assert_ne!(
            workspace_device, cross_volume_device,
            "cross-volume fixture remains on a distinct device"
        );
        assert!(
            self.cross_volume_directory
                .path()
                .starts_with(env!("CARGO_MANIFEST_DIR"))
        );
    }

    fn assert_python_script_unchanged(&self) {
        assert_eq!(
            std::fs::read_to_string(&self.python_script).unwrap(),
            self.python_source,
            "the fixture-owned child script remains unchanged"
        );
    }
}
