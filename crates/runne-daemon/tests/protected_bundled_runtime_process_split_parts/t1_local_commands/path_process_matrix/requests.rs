use std::{os::unix::fs::MetadataExt as _, path::Path};

use super::PathProcessMatrix;
use super::python_child::{PYTHON_MATRIX, python_literal};
use super::{
    CHILD_ARGUMENT_WITH_QUOTES, CHILD_ARGUMENT_WITH_SPACES, CHILD_ENV_NAME, CHILD_ENV_VALUE,
    CROSS_VOLUME_SEED,
};

impl PathProcessMatrix {
    pub(in crate::t1_local_commands::permission_modes) fn new(
        project_directory: &Path,
        payload: &str,
    ) -> Self {
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

    pub(in crate::t1_local_commands::permission_modes) fn cwd(&self) -> &Path {
        &self.fixture_cwd
    }

    pub(in crate::t1_local_commands::permission_modes) fn shell_script(&self) -> String {
        format!(
            "python3 {} \"$0\" \"$1\" 2> {}",
            super::super::filesystem_matrix::shell_quote_relative(
                &self.fixture_cwd,
                &self.python_script
            ),
            super::super::filesystem_matrix::shell_quote_relative(
                &self.fixture_cwd,
                &self.python_stderr
            )
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

    pub(in crate::t1_local_commands::permission_modes) fn request(
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

    pub(in crate::t1_local_commands::permission_modes) fn changed_intent_requests(
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
}
