use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(in crate::command_reconciliation) struct LocalCommandWire {
    executable: LocalExecutableWire,
    cwd: String,
    argv: Vec<String>,
    env: Vec<LocalEnvironmentWire>,
}

#[derive(Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LocalExecutableWire {
    WorkspaceRelative(String),
    SystemProgram(String),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LocalEnvironmentWire {
    key: String,
    value: String,
}

impl LocalCommandWire {
    pub(super) fn into_domain(self) -> Option<runne_domain::task_run::TaskRunLocalCommand> {
        let executable = match self.executable {
            LocalExecutableWire::WorkspaceRelative(value) => {
                runne_domain::task_run::TaskRunExecutable::workspace_relative(value).ok()?
            }
            LocalExecutableWire::SystemProgram(value) => {
                runne_domain::task_run::TaskRunExecutable::system_program(value).ok()?
            }
        };
        let env = self
            .env
            .into_iter()
            .map(|entry| (entry.key, entry.value))
            .collect();
        runne_domain::task_run::TaskRunLocalCommand::new(executable, self.cwd, self.argv, env).ok()
    }
}
