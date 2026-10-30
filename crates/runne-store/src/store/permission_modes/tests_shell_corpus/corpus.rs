//! Data and printf semantics reused from the daemon t1_local_commands/shell_corpus.rs.
use runne_domain::task_run::{TaskRunExecutable, TaskRunLocalCommand};
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
};

const ARGUMENT_WITH_SPACES: &str = "argument with spaces";
const ARGUMENT_WITH_QUOTES: &str = "value with 'single' and \"double\" quotes";
const ENVIRONMENT_VALUE: &str = "fixture-only value with 'quotes'";
const ATTACK_LOOKING_VALUE: &str = "$(touch shell-corpus-marker)";
const CWD: &str = "r08-path-process-cwd";

pub(super) struct Corpus {
    output: PathBuf,
    marker: PathBuf,
}

impl Corpus {
    pub(super) fn new(workspace: &Path) -> Self {
        std::fs::create_dir(workspace.join(CWD)).unwrap();
        Self {
            output: workspace.join("r08-shell-corpus-output"),
            marker: workspace.join(CWD).join("shell-corpus-marker"),
        }
    }

    pub(super) fn command(&self) -> TaskRunLocalCommand {
        // Same relative, single-quoted destination as the daemon helper for this layout.
        let script = format!(
            "printf '%s\\n' \"arg0:$0\" \"arg1:$1\" \"env:$RUNNE_TEST_PATH_MATRIX_ONLY\" 'unicode:café 東京' 'brackets:[alpha] {{beta}} (gamma)' 'attack:{ATTACK_LOOKING_VALUE}' >> '../r08-shell-corpus-output'"
        );
        TaskRunLocalCommand::new(
            TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
            CWD.into(),
            vec![
                "tool".into(),
                "-c".into(),
                script,
                ARGUMENT_WITH_SPACES.into(),
                ARGUMENT_WITH_QUOTES.into(),
            ],
            vec![(
                "RUNNE_TEST_PATH_MATRIX_ONLY".into(),
                ENVIRONMENT_VALUE.into(),
            )],
        )
        .unwrap()
    }

    pub(super) fn assert_intent(command: &TaskRunLocalCommand) {
        assert_eq!(command.cwd(), CWD);
        assert_eq!(
            &command.argv()[3..],
            &[ARGUMENT_WITH_SPACES, ARGUMENT_WITH_QUOTES]
        );
        assert_eq!(
            command.env(),
            &[(
                "RUNNE_TEST_PATH_MATRIX_ONLY".to_owned(),
                ENVIRONMENT_VALUE.to_owned(),
            )]
        );
    }

    fn absent(path: &Path) {
        assert_eq!(
            std::fs::symlink_metadata(path).unwrap_err().kind(),
            ErrorKind::NotFound,
            "exact NotFound required; permission errors are not absence",
        );
    }

    pub(super) fn assert_pending(&self) {
        Self::absent(&self.output);
        Self::absent(&self.marker);
    }

    pub(super) fn assert_effects(&self) {
        let expected = format!(
            "arg0:{ARGUMENT_WITH_SPACES}\narg1:{ARGUMENT_WITH_QUOTES}\nenv:{ENVIRONMENT_VALUE}\nunicode:café 東京\nbrackets:[alpha] {{beta}} (gamma)\nattack:{ATTACK_LOOKING_VALUE}\n"
        );
        assert_eq!(std::fs::read(&self.output).unwrap(), expected.as_bytes());
        Self::absent(&self.marker);
    }
}
