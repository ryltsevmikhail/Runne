use super::super::{TaskRunExecutable, TaskRunInput, TaskRunLocalCommand};
use super::TaskRunSnapshotError;
use super::io::{In, Out};

pub(super) fn put(
    out: &mut Out,
    command: Option<&TaskRunLocalCommand>,
) -> Result<(), TaskRunSnapshotError> {
    match command {
        None => out.u8(0),
        Some(command) => {
            out.u8(1);
            match command.executable() {
                TaskRunExecutable::WorkspaceRelative(value) => {
                    out.u8(1);
                    out.string(value)?;
                }
                TaskRunExecutable::SystemProgram(value) => {
                    out.u8(2);
                    out.string(value)?;
                }
            }
            out.string(command.cwd())?;
            out.len(command.argv().len())?;
            for value in command.argv() {
                out.string(value)?;
            }
            out.len(command.env().len())?;
            for (key, value) in command.env() {
                out.string(key)?;
                out.string(value)?;
            }
        }
    }
    Ok(())
}

pub(super) fn get(
    input: &mut In<'_>,
    task_input: TaskRunInput,
) -> Result<TaskRunInput, TaskRunSnapshotError> {
    match input.u8()? {
        0 => Ok(task_input),
        1 => {
            let executable = match input.u8()? {
                1 => TaskRunExecutable::workspace_relative(input.string()?),
                2 => TaskRunExecutable::system_program(input.string()?),
                _ => return Err(TaskRunSnapshotError::InvalidEncoding),
            }
            .map_err(|_| TaskRunSnapshotError::InvalidState)?;
            let cwd = input.string()?;
            let argc = input.len()?;
            if argc == 0 || argc > super::super::MAX_LOCAL_COMMAND_ARGV {
                return Err(TaskRunSnapshotError::InvalidEncoding);
            }
            let mut argv = Vec::with_capacity(argc);
            for _ in 0..argc {
                argv.push(input.string()?);
            }
            let envc = input.len()?;
            if envc > super::super::MAX_LOCAL_COMMAND_ENV {
                return Err(TaskRunSnapshotError::InvalidEncoding);
            }
            let mut env = Vec::with_capacity(envc);
            for _ in 0..envc {
                env.push((input.string()?, input.string()?));
            }
            let command = TaskRunLocalCommand::new(executable, cwd, argv, env)
                .map_err(|_| TaskRunSnapshotError::InvalidState)?;
            task_input
                .with_local_command(command)
                .map_err(|_| TaskRunSnapshotError::InvalidState)
        }
        _ => Err(TaskRunSnapshotError::InvalidEncoding),
    }
}
