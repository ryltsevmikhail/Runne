use std::{
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
};

const CHILD_ARGUMENT_WITH_SPACES: &str = "argument with spaces";
const CHILD_ARGUMENT_WITH_QUOTES: &str = "value with 'single' and \"double\" quotes";
const CHILD_ENV_NAME: &str = "RUNNE_TEST_PATH_MATRIX_ONLY";
const CHILD_ENV_VALUE: &str = "fixture-only value with 'quotes'";
const CROSS_VOLUME_SEED: &str = "cross-volume-input\n";

pub(super) struct PathProcessMatrix {
    workspace: PathBuf,
    fixture_cwd: PathBuf,
    fixture_cwd_relative: String,
    sibling: PathBuf,
    symlink_target: PathBuf,
    symlink_in_workspace: PathBuf,
    hardlink_source: PathBuf,
    hardlink_in_sibling: PathBuf,
    rename_source: PathBuf,
    rename_target: PathBuf,
    replace_source: PathBuf,
    replace_target: PathBuf,
    case_upper: PathBuf,
    case_lower: PathBuf,
    case_log: PathBuf,
    child_marker: PathBuf,
    python_script: PathBuf,
    python_stderr: PathBuf,
    python_source: String,
    hidden_device_directory: tempfile::TempDir,
    hidden_device_source: PathBuf,
    cross_volume_directory: tempfile::TempDir,
    cross_volume_source: PathBuf,
    cross_volume_output: PathBuf,
    cross_volume_link_target: PathBuf,
    cross_volume_rename_target: PathBuf,
}

impl PathProcessMatrix {
    pub(super) fn new(project_directory: &Path, payload: &str) -> Self {
        let sibling = project_directory
            .parent()
            .expect("fixture workspace has a parent")
            .join(format!("{payload}-path-process-sibling"));
        std::fs::create_dir(&sibling).expect("create path-process sibling");
        let fixture_cwd_relative = format!("{payload}-path-process-cwd");
        let fixture_cwd = project_directory.join(&fixture_cwd_relative);
        std::fs::create_dir(&fixture_cwd).expect("create nondefault child working directory");

        let hidden_device_directory = tempfile::Builder::new()
            .prefix(&format!("runne-path-process-{payload}-"))
            .tempdir_in("/dev/shm")
            .expect("create owned /dev/shm device-visibility canary");
        let cross_volume_directory = tempfile::Builder::new()
            .prefix(&format!("runne-path-process-xdev-{payload}-"))
            .tempdir_in(env!("CARGO_MANIFEST_DIR"))
            .expect("create owned cross-volume fixture on the worktree device");
        let mut matrix = Self {
            workspace: project_directory.to_owned(),
            fixture_cwd: fixture_cwd.clone(),
            fixture_cwd_relative,
            sibling: sibling.clone(),
            symlink_target: sibling.join("symlink-target"),
            symlink_in_workspace: project_directory.join(format!("{payload}-workspace-symlink")),
            hardlink_source: project_directory.join(format!("{payload}-hardlink-source")),
            hardlink_in_sibling: sibling.join("hardlink-alias"),
            rename_source: project_directory.join(format!("{payload}-rename-source")),
            rename_target: sibling.join("renamed-from-workspace"),
            replace_source: project_directory.join(format!("{payload}-replace-source")),
            replace_target: sibling.join("replacement-target"),
            case_upper: fixture_cwd.join("CaseProbe"),
            case_lower: fixture_cwd.join("caseprobe"),
            case_log: fixture_cwd.join("case-sensitivity.log"),
            child_marker: sibling.join("child-append-marker"),
            python_script: fixture_cwd.join("path-process-matrix.py"),
            python_stderr: fixture_cwd.join("path-process-stderr.txt"),
            python_source: String::new(),
            hidden_device_source: hidden_device_directory.path().join("input"),
            hidden_device_directory,
            cross_volume_source: cross_volume_directory.path().join("input"),
            cross_volume_output: cross_volume_directory.path().join("output"),
            cross_volume_link_target: project_directory.join(format!("{payload}-xdev-link")),
            cross_volume_rename_target: project_directory.join(format!("{payload}-xdev-rename")),
            cross_volume_directory,
        };
        std::fs::write(&matrix.symlink_target, "symlink-seed\n").expect("seed symlink target");
        std::fs::write(&matrix.hardlink_source, "hardlink-seed\n").expect("seed hardlink source");
        std::fs::write(&matrix.rename_source, "rename-source\n").expect("seed rename source");
        std::fs::write(&matrix.replace_source, "replacement-new\n")
            .expect("seed replacement source");
        std::fs::write(&matrix.replace_target, "replacement-old\n")
            .expect("seed replacement target");
        std::fs::write(&matrix.cross_volume_source, CROSS_VOLUME_SEED)
            .expect("seed owned cross-volume input");
        std::fs::write(&matrix.hidden_device_source, CROSS_VOLUME_SEED)
            .expect("seed owned /dev/shm visibility canary");
        matrix.python_source = matrix.render_python_source();
        std::fs::write(&matrix.python_script, matrix.python_source.as_bytes())
            .expect("write fixture-owned path-process child script");

        assert_eq!(
            std::fs::metadata(&matrix.workspace).unwrap().dev(),
            std::fs::metadata(&sibling).unwrap().dev(),
            "workspace and owned sibling must share a filesystem for rename tests"
        );
        assert_ne!(
            std::fs::metadata(&matrix.workspace).unwrap().dev(),
            std::fs::metadata(&matrix.cross_volume_source)
                .unwrap()
                .dev(),
            "worktree fixture and workspace do not expose distinct st_dev values"
        );
        matrix.assert_pending();
        matrix
    }

    pub(super) fn shell_script(&self) -> String {
        format!(
            "python3 {} \"$0\" \"$1\" 2> {}",
            shell_quote(&self.python_script.display().to_string()),
            shell_quote(&self.python_stderr.display().to_string())
        )
    }

    fn render_python_source(&self) -> String {
        let mut source = PYTHON_MATRIX.to_owned();
        for (placeholder, path) in [
            ("@@WORKSPACE@@", &self.workspace),
            ("@@SIBLING@@", &self.sibling),
            ("@@SYMLINK_TARGET@@", &self.symlink_target),
            ("@@SYMLINK@@", &self.symlink_in_workspace),
            ("@@HARDLINK_SOURCE@@", &self.hardlink_source),
            ("@@HARDLINK_ALIAS@@", &self.hardlink_in_sibling),
            ("@@RENAME_SOURCE@@", &self.rename_source),
            ("@@RENAME_TARGET@@", &self.rename_target),
            ("@@REPLACE_SOURCE@@", &self.replace_source),
            ("@@REPLACE_TARGET@@", &self.replace_target),
            ("@@CASE_UPPER@@", &self.case_upper),
            ("@@CASE_LOWER@@", &self.case_lower),
            ("@@CASE_LOG@@", &self.case_log),
            ("@@CHILD_MARKER@@", &self.child_marker),
            ("@@HIDDEN_DEVICE_SOURCE@@", &self.hidden_device_source),
            ("@@CROSS_SOURCE@@", &self.cross_volume_source),
            ("@@CROSS_OUTPUT@@", &self.cross_volume_output),
            ("@@CROSS_LINK_TARGET@@", &self.cross_volume_link_target),
            ("@@CROSS_RENAME_TARGET@@", &self.cross_volume_rename_target),
            ("@@FIXTURE_CWD@@", &self.fixture_cwd),
        ] {
            source = source.replace(placeholder, &python_literal(&path.display().to_string()));
        }
        source
    }

    pub(super) fn request(
        &self,
        conversation_id: runne_runtime_client::CanonicalId,
        workspace_id: runne_runtime_client::CanonicalId,
        payload: &str,
        script: &str,
    ) -> runne_runtime_client::SubmitTaskRunRequest {
        let command = self.command(script);
        runne_runtime_client::SubmitTaskRunRequest::new(
            runne_runtime_client::CommandIdentity::new(
                runne_runtime_client::CanonicalId::now_v7(),
                format!("t1-local-mode-{payload}"),
            )
            .expect("path-process command identity"),
            conversation_id,
            workspace_id,
            format!("Run one local permission-mode effect {payload}"),
        )
        .expect("valid path-process TaskRun")
        .with_local_command(command)
        .expect("select structured path-process command")
    }

    pub(super) fn changed_intent_requests(
        &self,
        request: &runne_runtime_client::SubmitTaskRunRequest,
        script: &str,
    ) -> Vec<runne_runtime_client::SubmitTaskRunRequest> {
        let original = self.command(script);
        let make_request = |executable, cwd, argv, env| {
            let command = runne_api::TaskRunLocalCommand::new(executable, cwd, argv, env)
                .expect("valid local-command intent variant");
            request
                .clone()
                .with_local_command(command)
                .expect("replace cloned local-command intent")
        };

        let executable = runne_api::TaskRunExecutable::workspace_relative(
            self.python_script
                .strip_prefix(&self.workspace)
                .expect("child script is inside the fixture workspace")
                .to_string_lossy()
                .into_owned(),
        )
        .expect("valid workspace-relative executable variant");
        let mut argv = original.argv().to_vec();
        argv[3] = "changed structured argument".into();
        let mut env = original.env().to_vec();
        env[0].1 = "changed fixture-only value".into();

        vec![
            make_request(
                executable,
                original.cwd().to_owned(),
                original.argv().to_vec(),
                original.env().to_vec(),
            ),
            make_request(
                original.executable().clone(),
                original.cwd().to_owned(),
                argv,
                original.env().to_vec(),
            ),
            make_request(
                original.executable().clone(),
                original.cwd().to_owned(),
                original.argv().to_vec(),
                env,
            ),
            make_request(
                original.executable().clone(),
                ".".into(),
                original.argv().to_vec(),
                original.env().to_vec(),
            ),
        ]
    }

    fn command(&self, script: &str) -> runne_api::TaskRunLocalCommand {
        runne_api::TaskRunLocalCommand::new(
            runne_api::TaskRunExecutable::system_program("shell".into()).unwrap(),
            self.fixture_cwd_relative.clone(),
            vec![
                "bash".into(),
                "-c".into(),
                script.to_owned(),
                CHILD_ARGUMENT_WITH_SPACES.into(),
                CHILD_ARGUMENT_WITH_QUOTES.into(),
            ],
            vec![(CHILD_ENV_NAME.into(), CHILD_ENV_VALUE.into())],
        )
        .expect("valid structured path-process command")
    }

    pub(super) fn assert_pending(&self) {
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

    pub(super) fn assert_effects(&self) {
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

fn python_literal(value: &str) -> String {
    serde_json::to_string(value).expect("encode fixture path as a Python string literal")
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

const PYTHON_MATRIX: &str = r#"
import errno
import os
import pathlib
import sys

workspace = pathlib.Path(@@WORKSPACE@@)
sibling = pathlib.Path(@@SIBLING@@)
symlink_target = pathlib.Path(@@SYMLINK_TARGET@@)
symlink_path = pathlib.Path(@@SYMLINK@@)
hardlink_source = pathlib.Path(@@HARDLINK_SOURCE@@)
hardlink_alias = pathlib.Path(@@HARDLINK_ALIAS@@)
rename_source = pathlib.Path(@@RENAME_SOURCE@@)
rename_target = pathlib.Path(@@RENAME_TARGET@@)
replace_source = pathlib.Path(@@REPLACE_SOURCE@@)
replace_target = pathlib.Path(@@REPLACE_TARGET@@)
case_upper = pathlib.Path(@@CASE_UPPER@@)
case_lower = pathlib.Path(@@CASE_LOWER@@)
case_log = pathlib.Path(@@CASE_LOG@@)
child_marker = pathlib.Path(@@CHILD_MARKER@@)
hidden_device_source = pathlib.Path(@@HIDDEN_DEVICE_SOURCE@@)
cross_source = pathlib.Path(@@CROSS_SOURCE@@)
cross_output = pathlib.Path(@@CROSS_OUTPUT@@)
cross_link_target = pathlib.Path(@@CROSS_LINK_TARGET@@)
cross_rename_target = pathlib.Path(@@CROSS_RENAME_TARGET@@)
fixture_cwd = pathlib.Path(@@FIXTURE_CWD@@)

workspace_device = os.stat(workspace).st_dev
assert os.stat(sibling).st_dev == workspace_device
os.symlink(symlink_target, symlink_path)
with symlink_path.open("a", encoding="utf-8") as target:
    target.write("symlink-followed\n")

os.link(hardlink_source, hardlink_alias)
source_stat = os.stat(hardlink_source)
alias_stat = os.stat(hardlink_alias)
assert (source_stat.st_dev, source_stat.st_ino) == (alias_stat.st_dev, alias_stat.st_ino)
with hardlink_alias.open("a", encoding="utf-8") as target:
    target.write("hardlink-followed\n")

assert os.stat(rename_source).st_dev == os.stat(rename_target.parent).st_dev
os.rename(rename_source, rename_target)
assert replace_target.read_text(encoding="utf-8") == "replacement-old\n"
os.replace(replace_source, replace_target)

case_upper.write_text("upper\n", encoding="utf-8")
case_lower.write_text("lower\n", encoding="utf-8")
same_case_file = os.path.samefile(case_upper, case_lower)
if same_case_file:
    assert case_upper.read_text(encoding="utf-8") == "lower\n"
    assert case_lower.read_text(encoding="utf-8") == "lower\n"
else:
    assert case_upper.read_text(encoding="utf-8") == "upper\n"
    assert case_lower.read_text(encoding="utf-8") == "lower\n"
case_log.write_text("case_sensitive=" + str(not same_case_file).lower() + "\n", encoding="utf-8")

try:
    hidden_device_source.stat()
except FileNotFoundError:
    pass
else:
    raise AssertionError("the host /dev/shm canary is visible inside the child namespace")

cross_device = os.stat(cross_source).st_dev
assert cross_device != workspace_device, "cross-volume fixture requires distinct st_dev"
cross_contents = cross_source.read_text(encoding="utf-8")
assert cross_contents == "cross-volume-input\n"
cross_output.write_text("cross-volume-output:" + cross_contents, encoding="utf-8")
try:
    os.link(cross_source, cross_link_target)
except OSError as error:
    assert error.errno == errno.EXDEV, "cross-volume hard link failed with errno " + str(error.errno)
else:
    raise AssertionError("cross-volume hard link unexpectedly succeeded")
try:
    os.rename(cross_source, cross_rename_target)
except OSError as error:
    assert error.errno == errno.EXDEV, "cross-volume rename failed with errno " + str(error.errno)
else:
    raise AssertionError("cross-volume rename unexpectedly succeeded")
assert cross_source.exists()

expected_arguments = ["argument with spaces", "value with 'single' and \"double\" quotes"]
assert sys.argv[1:] == expected_arguments, "structured argv was changed by the shell"
assert os.environ["RUNNE_TEST_PATH_MATRIX_ONLY"] == "fixture-only value with 'quotes'"
assert os.path.samefile(pathlib.Path.cwd(), fixture_cwd), "child did not inherit the fixture cwd"
marker = (
    "argv0=" + sys.argv[1]
    + ";argv1=" + sys.argv[2]
    + ";env=" + os.environ["RUNNE_TEST_PATH_MATRIX_ONLY"]
    + ";cwd=" + pathlib.Path.cwd().name
    + "\n"
)
with child_marker.open("a", encoding="utf-8") as output:
    output.write(marker)
"#;
