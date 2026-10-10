use std::path::{Path, PathBuf};

const WORKSPACE_READ_PROOF: &str = "workspace-read-proof";
const SIBLING_READ_PROOF: &str = "sibling-read-proof";
const WORKSPACE_APPEND_SEED: &str = "workspace-append-before\n";
const SIBLING_APPEND_SEED: &str = "sibling-append-before\n";

pub(super) struct PermissionModeFilesystemMatrix {
    workspace_read: PathBuf,
    workspace_append: PathBuf,
    workspace_create: PathBuf,
    workspace_delete: PathBuf,
    sibling_directory: PathBuf,
    sibling_read: PathBuf,
    sibling_append: PathBuf,
    sibling_create: PathBuf,
    sibling_delete: PathBuf,
}

impl PermissionModeFilesystemMatrix {
    pub(super) fn new(project_directory: &Path, payload: &str) -> Self {
        let sibling_directory = project_directory
            .parent()
            .expect("fixture workspace has a parent directory")
            .join(format!("{payload}-outside-workspace"));
        std::fs::create_dir(&sibling_directory).expect("create fixture sibling directory");
        let matrix = Self {
            workspace_read: project_directory.join(format!("{payload}-workspace-read")),
            workspace_append: project_directory.join(format!("{payload}-workspace-append")),
            workspace_create: project_directory.join(format!("{payload}-workspace-create")),
            workspace_delete: project_directory.join(format!("{payload}-workspace-delete")),
            sibling_read: sibling_directory.join("read-seed"),
            sibling_append: sibling_directory.join("append-seed"),
            sibling_create: sibling_directory.join("created-output"),
            sibling_delete: sibling_directory.join("delete-canary"),
            sibling_directory,
        };
        std::fs::write(&matrix.workspace_read, format!("{WORKSPACE_READ_PROOF}\n"))
            .expect("seed workspace read proof");
        std::fs::write(&matrix.workspace_append, WORKSPACE_APPEND_SEED)
            .expect("seed workspace append file");
        std::fs::write(&matrix.workspace_delete, "workspace-delete-canary\n")
            .expect("seed workspace delete canary");
        std::fs::write(&matrix.sibling_read, format!("{SIBLING_READ_PROOF}\n"))
            .expect("seed sibling read proof");
        std::fs::write(&matrix.sibling_append, SIBLING_APPEND_SEED)
            .expect("seed sibling append file");
        std::fs::write(&matrix.sibling_delete, "sibling-delete-canary\n")
            .expect("seed sibling delete canary");
        assert!(
            !matrix.workspace_create.exists() && !matrix.sibling_create.exists(),
            "create targets start absent"
        );
        matrix
    }

    pub(super) fn shell_script(&self, cwd: &Path) -> String {
        let workspace_read = shell_quote_relative(cwd, &self.workspace_read);
        let workspace_append = shell_quote_relative(cwd, &self.workspace_append);
        let workspace_create = shell_quote_relative(cwd, &self.workspace_create);
        let workspace_delete = shell_quote_relative(cwd, &self.workspace_delete);
        let sibling_read = shell_quote_relative(cwd, &self.sibling_read);
        let sibling_append = shell_quote_relative(cwd, &self.sibling_append);
        let sibling_create = shell_quote_relative(cwd, &self.sibling_create);
        let sibling_delete = shell_quote_relative(cwd, &self.sibling_delete);
        format!(
            "test \"$(cat -- {workspace_read})\" = '{WORKSPACE_READ_PROOF}'; cat -- {workspace_read} >> {workspace_append}; printf '%s\\n' 'workspace-created-content' > {workspace_create}; rm -- {workspace_delete}; test \"$(cat -- {sibling_read})\" = '{SIBLING_READ_PROOF}'; cat -- {sibling_read} >> {sibling_append}; printf '%s\\n' 'sibling-created-content' > {sibling_create}; rm -- {sibling_delete}"
        )
    }

    pub(super) fn assert_pending(&self, before_network: &Path, after_network: &Path) {
        assert!(self.sibling_directory.is_dir());
        assert_eq!(
            std::fs::read_to_string(&self.workspace_read).unwrap(),
            format!("{WORKSPACE_READ_PROOF}\n")
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_append).unwrap(),
            WORKSPACE_APPEND_SEED
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_delete).unwrap(),
            "workspace-delete-canary\n"
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_read).unwrap(),
            format!("{SIBLING_READ_PROOF}\n")
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_append).unwrap(),
            SIBLING_APPEND_SEED
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_delete).unwrap(),
            "sibling-delete-canary\n"
        );
        assert!(
            !self.workspace_create.exists()
                && !self.sibling_create.exists()
                && !before_network.exists()
                && !after_network.exists(),
            "pending process has no filesystem outputs"
        );
    }

    pub(super) fn assert_effects(&self) {
        assert_eq!(
            std::fs::read_to_string(&self.workspace_read).unwrap(),
            format!("{WORKSPACE_READ_PROOF}\n"),
            "the workspace read seed remains unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_append).unwrap(),
            format!("{WORKSPACE_APPEND_SEED}{WORKSPACE_READ_PROOF}\n"),
            "workspace read bytes were appended exactly once"
        );
        assert_eq!(
            std::fs::read_to_string(&self.workspace_create).unwrap(),
            "workspace-created-content\n"
        );
        assert!(!self.workspace_delete.exists());
        assert_eq!(
            std::fs::read_to_string(&self.sibling_read).unwrap(),
            format!("{SIBLING_READ_PROOF}\n"),
            "the sibling read seed remains unchanged"
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_append).unwrap(),
            format!("{SIBLING_APPEND_SEED}{SIBLING_READ_PROOF}\n"),
            "sibling read bytes were appended exactly once"
        );
        assert_eq!(
            std::fs::read_to_string(&self.sibling_create).unwrap(),
            "sibling-created-content\n"
        );
        assert!(!self.sibling_delete.exists());
    }
}

pub(super) fn shell_quote_path(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\\''"))
}

/// Renders a fixture path relative to the structured command's working
/// directory. The approval review embeds the argv verbatim, so fixture
/// scripts must stay independent of the absolute temp-path depth (the
/// canonical CI namespace nests TMPDIR far deeper than a dev shell while the
/// runtime keeps a fixed 4096-byte review bound).
pub(crate) fn shell_quote_relative(cwd: &Path, target: &Path) -> String {
    let mut prefix = cwd;
    let mut ups = 0_usize;
    loop {
        if let Ok(rest) = target.strip_prefix(prefix) {
            let relative = if rest.as_os_str().is_empty() {
                ".".to_owned()
            } else {
                format!("{}{}", "../".repeat(ups), rest.display())
            };
            return shell_quote_path(Path::new(&relative));
        }
        match prefix.parent() {
            Some(parent) if ups < 8 => {
                prefix = parent;
                ups += 1;
            }
            _ => panic!(
                "fixture target {target:?} shares no root with the command cwd {cwd:?}; \
                 cross-device fixtures must stay inside the python child source"
            ),
        }
    }
}
