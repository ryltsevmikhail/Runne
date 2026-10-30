use runne_domain::task_run::{TaskRunExecutable, TaskRunLocalCommand};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

const PAYLOAD: &[u8] = b"#!/bin/sh\nprintf '%s\\n' replacement > replacement-effect\n";
const REPLACEMENT: &str = "replacement-payload";

pub(super) struct Paths(PathBuf);
impl Paths {
    pub(super) fn new(workspace: &Path) -> Self {
        Self(workspace.to_owned())
    }
    pub(super) fn command(&self) -> TaskRunLocalCommand {
        TaskRunLocalCommand::new(
            TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
            ".".into(),
            vec![
                "tool".into(),
                "-c".into(),
                "printf '%s\\n' original > original-effect".into(),
            ],
            vec![],
        )
        .unwrap()
    }
    pub(super) fn tool(&self) -> PathBuf {
        self.0.join("tool")
    }
    pub(super) fn replace(&self, original: &[u8]) {
        assert_eq!(std::fs::read(self.tool()).unwrap(), original);
        assert!(std::fs::symlink_metadata(self.tool()).unwrap().is_file());
        absent(&self.0.join("tool-original"));
        absent(&self.0.join(REPLACEMENT));
        let payload = self.0.join(REPLACEMENT);
        std::fs::write(&payload, PAYLOAD).unwrap();
        std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(self.tool(), self.0.join("tool-original")).unwrap();
        symlink(REPLACEMENT, self.tool()).unwrap();
        self.assert_replaced(original);
    }
    pub(super) fn assert_replaced(&self, original: &[u8]) {
        assert!(
            std::fs::symlink_metadata(self.tool())
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            std::fs::read_link(self.tool()).unwrap(),
            Path::new(REPLACEMENT)
        );
        assert!(
            std::fs::symlink_metadata(self.0.join(REPLACEMENT))
                .unwrap()
                .is_file()
        );
        assert!(
            std::fs::symlink_metadata(self.0.join("tool-original"))
                .unwrap()
                .is_file()
        );
        assert_eq!(
            std::fs::read(self.0.join("tool-original")).unwrap(),
            original
        );
        assert_eq!(std::fs::read(self.0.join(REPLACEMENT)).unwrap(), PAYLOAD);
        assert_eq!(std::fs::read(self.tool()).unwrap(), PAYLOAD);
    }
    pub(super) fn pending(&self) {
        absent(&self.0.join("original-effect"));
        absent(&self.0.join("replacement-effect"));
    }
    pub(super) fn effects(&self) {
        assert!(
            std::fs::symlink_metadata(self.0.join("original-effect"))
                .unwrap()
                .is_file()
        );
        assert_eq!(
            std::fs::read(self.0.join("original-effect")).unwrap(),
            b"original\n"
        );
        absent(&self.0.join("replacement-effect"));
    }
}

fn absent(path: &Path) {
    assert_eq!(
        std::fs::symlink_metadata(path).unwrap_err().kind(),
        ErrorKind::NotFound
    );
}
