use std::path::{Path, PathBuf};

const ARGUMENT_WITH_SPACES: &str = "argument with spaces";
const ARGUMENT_WITH_QUOTES: &str = "value with 'single' and \"double\" quotes";
const ENVIRONMENT_VALUE: &str = "fixture-only value with 'quotes'";
const ATTACK_LOOKING_VALUE: &str = "$(touch shell-corpus-marker)";

pub(super) struct ShellCorpus {
    output: PathBuf,
    marker: PathBuf,
}

impl ShellCorpus {
    pub(super) fn new(project_directory: &Path, payload: &str) -> Self {
        Self {
            output: project_directory.join(format!("{payload}-shell-corpus-output")),
            marker: project_directory
                .join(format!("{payload}-path-process-cwd"))
                .join("shell-corpus-marker"),
        }
    }

    pub(super) fn shell_script(&self, cwd: &Path) -> String {
        format!(
            "printf '%s\\n' \"arg0:$0\" \"arg1:$1\" \"env:$RUNNE_TEST_PATH_MATRIX_ONLY\" 'unicode:café 東京' 'brackets:[alpha] {{beta}} (gamma)' 'attack:{ATTACK_LOOKING_VALUE}' >> {}",
            super::filesystem_matrix::shell_quote_relative(cwd, &self.output)
        )
    }

    pub(super) fn assert_pending(&self) {
        assert!(!self.output.exists(), "shell corpus ran before approval");
        assert!(
            !self.marker.exists(),
            "shell corpus evaluated its data value"
        );
    }

    pub(super) fn assert_effects(&self) {
        assert_eq!(
            std::fs::read_to_string(&self.output).expect("read shell corpus output"),
            format!(
                "arg0:{ARGUMENT_WITH_SPACES}\narg1:{ARGUMENT_WITH_QUOTES}\nenv:{ENVIRONMENT_VALUE}\nunicode:café 東京\nbrackets:[alpha] {{beta}} (gamma)\nattack:{ATTACK_LOOKING_VALUE}\n"
            ),
            "shell substitutions and quoting preserve exact fixture data"
        );
        assert!(
            !self.marker.exists(),
            "attack-looking shell data must never be evaluated"
        );
    }
}
