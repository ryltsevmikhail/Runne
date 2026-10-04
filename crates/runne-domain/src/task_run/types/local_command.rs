use sha2::{Digest, Sha256};

pub const MAX_LOCAL_COMMAND_ARGV: usize = 256;
pub const MAX_LOCAL_COMMAND_ENV: usize = 256;
pub const MAX_LOCAL_COMMAND_BYTES: usize = 128 * 1024;

/// Closed executable origin; system names are catalog IDs, never filesystem paths.
#[derive(Clone, PartialEq, Eq)]
pub enum TaskRunExecutable {
    WorkspaceRelative(String),
    SystemProgram(String),
}

impl std::fmt::Debug for TaskRunExecutable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TaskRunExecutable([REDACTED])")
    }
}

impl TaskRunExecutable {
    pub fn workspace_relative(path: String) -> Result<Self, TaskRunLocalCommandError> {
        relative_path(&path, false)
            .then_some(Self::WorkspaceRelative(path))
            .ok_or(TaskRunLocalCommandError)
    }

    pub fn system_program(catalog_id: String) -> Result<Self, TaskRunLocalCommandError> {
        valid_catalog_id(&catalog_id)
            .then_some(Self::SystemProgram(catalog_id))
            .ok_or(TaskRunLocalCommandError)
    }

    pub fn value(&self) -> &str {
        match self {
            Self::WorkspaceRelative(path) | Self::SystemProgram(path) => path,
        }
    }
}

/// A bounded command intent. Executable and cwd are resolved to held handles
/// only under the protected runtime root and broker policy.
#[derive(Clone, PartialEq, Eq)]
pub struct TaskRunLocalCommand {
    executable: TaskRunExecutable,
    cwd: String,
    argv: Vec<String>,
    env: Vec<(String, String)>,
}

impl std::fmt::Debug for TaskRunLocalCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TaskRunLocalCommand")
            .field("redacted", &true)
            .field("executable", &"[REDACTED]")
            .field("cwd", &"[REDACTED]")
            .finish()
    }
}

impl TaskRunLocalCommand {
    pub fn new(
        executable: TaskRunExecutable,
        cwd: String,
        argv: Vec<String>,
        mut env: Vec<(String, String)>,
    ) -> Result<Self, TaskRunLocalCommandError> {
        if !valid_executable(&executable)
            || !relative_path(&cwd, true)
            || argv.is_empty()
            || argv.len() > MAX_LOCAL_COMMAND_ARGV
            || env.len() > MAX_LOCAL_COMMAND_ENV
        {
            return Err(TaskRunLocalCommandError);
        }
        let mut size = executable.value().len().saturating_add(cwd.len());
        for argument in &argv {
            if argument.as_bytes().contains(&0) || argument.len() > 16 * 1024 {
                return Err(TaskRunLocalCommandError);
            }
            size = size.saturating_add(argument.len());
        }
        for (key, value) in &env {
            if !env_key(key) || value.as_bytes().contains(&0) || value.len() > 16 * 1024 {
                return Err(TaskRunLocalCommandError);
            }
            size = size.saturating_add(key.len()).saturating_add(value.len());
        }
        if size > MAX_LOCAL_COMMAND_BYTES {
            return Err(TaskRunLocalCommandError);
        }
        env.sort_by(|left, right| left.0.cmp(&right.0));
        if env.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(TaskRunLocalCommandError);
        }
        Ok(Self {
            executable,
            cwd,
            argv,
            env,
        })
    }

    pub fn executable(&self) -> &TaskRunExecutable {
        &self.executable
    }
    pub fn cwd(&self) -> &str {
        &self.cwd
    }
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
    pub fn env(&self) -> &[(String, String)] {
        &self.env
    }

    /// Digest used to bind approval to this exact structured intent.
    pub fn intent_digest(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"runne-taskrun-local-command-v1\0");
        match &self.executable {
            TaskRunExecutable::WorkspaceRelative(_) => hash.update([1]),
            TaskRunExecutable::SystemProgram(_) => hash.update([2]),
        }
        field(&mut hash, self.executable.value().as_bytes());
        field(&mut hash, self.cwd.as_bytes());
        hash.update((self.argv.len() as u32).to_be_bytes());
        for argument in &self.argv {
            field(&mut hash, argument.as_bytes());
        }
        hash.update((self.env.len() as u32).to_be_bytes());
        for (key, value) in &self.env {
            field(&mut hash, key.as_bytes());
            field(&mut hash, value.as_bytes());
        }
        hash.finalize().into()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TaskRunLocalCommandError;

fn relative_path(value: &str, allow_dot: bool) -> bool {
    !value.is_empty()
        && value.len() <= 4096
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.as_bytes().contains(&0)
        && (allow_dot && value == "."
            || value
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."))
}

fn env_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
        && value.len() <= 128
}

fn valid_executable(value: &TaskRunExecutable) -> bool {
    match value {
        TaskRunExecutable::WorkspaceRelative(path) => relative_path(path, false),
        TaskRunExecutable::SystemProgram(id) => valid_catalog_id(id),
    }
}

fn valid_catalog_id(value: &str) -> bool {
    value.len() <= 128
        && !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u32).to_be_bytes());
    hash.update(bytes);
}

#[cfg(test)]
mod local_command_tests {
    use super::*;

    fn command(env: Vec<(String, String)>) -> TaskRunLocalCommand {
        TaskRunLocalCommand::new(
            TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
            ".".into(),
            vec!["tool".into(), "--check".into()],
            env,
        )
        .unwrap()
    }

    #[test]
    fn command_digest_binds_structured_fields_and_canonicalizes_environment() {
        let left = command(vec![("B".into(), "2".into()), ("A".into(), "1".into())]);
        let reordered = command(vec![("A".into(), "1".into()), ("B".into(), "2".into())]);
        let changed = TaskRunLocalCommand::new(
            TaskRunExecutable::workspace_relative("bin/tool".into()).unwrap(),
            ".".into(),
            vec!["tool".into(), "--run".into()],
            vec![],
        )
        .unwrap();
        assert_eq!(left.intent_digest(), reordered.intent_digest());
        assert_ne!(left.intent_digest(), changed.intent_digest());
    }

    #[test]
    fn command_rejects_escape_duplicate_environment_and_unbounded_arguments() {
        assert!(TaskRunExecutable::workspace_relative("../tool".into()).is_err());
        assert!(
            TaskRunLocalCommand::new(
                TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
                "../".into(),
                vec!["x".into()],
                vec![],
            )
            .is_err()
        );
        assert!(
            TaskRunLocalCommand::new(
                TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
                ".".into(),
                vec!["x".into()],
                vec![("A".into(), "1".into()), ("A".into(), "2".into())],
            )
            .is_err()
        );
        assert!(
            TaskRunLocalCommand::new(
                TaskRunExecutable::workspace_relative("tool".into()).unwrap(),
                ".".into(),
                vec!["x\0".into()],
                vec![]
            )
            .is_err()
        );
    }

    #[test]
    fn constructor_revalidates_public_executable_variants() {
        for executable in [
            TaskRunExecutable::WorkspaceRelative("../escape".into()),
            TaskRunExecutable::WorkspaceRelative("/absolute".into()),
            TaskRunExecutable::WorkspaceRelative("bad\0path".into()),
            TaskRunExecutable::WorkspaceRelative("x".repeat(4097)),
            TaskRunExecutable::SystemProgram("bad id".into()),
            TaskRunExecutable::SystemProgram("x".repeat(129)),
        ] {
            assert!(
                TaskRunLocalCommand::new(executable, ".".into(), vec!["tool".into()], vec![])
                    .is_err()
            );
        }
    }

    #[test]
    fn provider_selection_and_local_command_are_mutually_exclusive_in_both_orders() {
        let profile = SelectedProviderProfile::new("profile/a".into(), [1; 32]).unwrap();
        let base = TaskRunInput::new("describe command".into()).unwrap();
        let command = command(vec![]);
        assert!(
            base.clone()
                .with_local_command(command.clone())
                .unwrap()
                .with_selected_profile(profile.clone())
                .is_err()
        );
        assert!(
            base.clone()
                .with_requested_model("model".into())
                .unwrap()
                .with_local_command(command.clone())
                .is_err()
        );
        assert!(
            base.clone()
                .with_selected_profile(profile)
                .unwrap()
                .with_local_command(command.clone())
                .is_err()
        );
        assert!(
            base.with_local_command(command)
                .unwrap()
                .with_requested_model("model".into())
                .is_err()
        );
    }
}
