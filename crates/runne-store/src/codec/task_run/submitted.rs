use super::*;

pub(super) fn encode(
    buf: &mut Vec<u8>,
    conversation_id: runne_domain::id::ConversationId,
    workspace_id: runne_domain::id::WorkspaceId,
    input: &runne_domain::task_run::TaskRunInput,
    version: u16,
) {
    buf.push(TAG_TASK_RUN_SUBMITTED);
    write_uuid(buf, conversation_id.as_bytes());
    write_uuid(buf, workspace_id.as_bytes());
    let prompt = input.prompt().as_bytes();
    buf.extend_from_slice(&(prompt.len() as u32).to_be_bytes());
    buf.extend_from_slice(prompt);
    if version >= 2 {
        match input.requested_model() {
            None => buf.push(0),
            Some(model) => {
                buf.push(1);
                buf.extend_from_slice(&(model.len() as u16).to_be_bytes());
                buf.extend_from_slice(model.as_bytes());
            }
        }
    }
    if version >= 3 {
        match input.selected_profile() {
            None => buf.push(0),
            Some(profile) => {
                buf.push(1);
                buf.extend_from_slice(&(profile.profile_id().len() as u16).to_be_bytes());
                buf.extend_from_slice(profile.profile_id().as_bytes());
                buf.extend_from_slice(profile.profile_digest());
            }
        }
    }
    if version >= 4 {
        match input.local_command() {
            None => buf.push(0),
            Some(command) => {
                buf.push(1);
                if version >= 5 {
                    match command.executable() {
                        runne_domain::task_run::TaskRunExecutable::WorkspaceRelative(_) => {
                            buf.push(1);
                        }
                        runne_domain::task_run::TaskRunExecutable::SystemProgram(_) => {
                            buf.push(2);
                        }
                    }
                }
                write_len_prefixed(buf, command.executable().value().as_bytes());
                write_len_prefixed(buf, command.cwd().as_bytes());
                buf.extend_from_slice(&(command.argv().len() as u16).to_be_bytes());
                for argument in command.argv() {
                    write_len_prefixed(buf, argument.as_bytes());
                }
                buf.extend_from_slice(&(command.env().len() as u16).to_be_bytes());
                for (key, value) in command.env() {
                    write_len_prefixed(buf, key.as_bytes());
                    write_len_prefixed(buf, value.as_bytes());
                }
            }
        }
    }
}

pub(super) fn decode(
    bytes: &[u8],
    pos: &mut usize,
    version: u16,
) -> Result<TaskRunEvent, StoreCodecError> {
    let conversation_id = runne_domain::id::ConversationId::from_bytes(read_uuid(bytes, pos)?);
    let workspace_id = runne_domain::id::WorkspaceId::from_bytes(read_uuid(bytes, pos)?);
    if pos.checked_add(4).ok_or(StoreCodecError::Truncated)? > bytes.len() {
        return Err(StoreCodecError::Truncated);
    }
    let prompt_len = u32::from_be_bytes(
        bytes[*pos..*pos + 4]
            .try_into()
            .map_err(|_| StoreCodecError::Truncated)?,
    ) as usize;
    *pos += 4;
    if prompt_len > 65_536 {
        return Err(StoreCodecError::Truncated);
    }
    let prompt_end = pos
        .checked_add(prompt_len)
        .ok_or(StoreCodecError::Truncated)?;
    let prompt = String::from_utf8(
        bytes
            .get(*pos..prompt_end)
            .ok_or(StoreCodecError::Truncated)?
            .to_vec(),
    )
    .map_err(|_| StoreCodecError::Truncated)?;
    *pos = prompt_end;
    let mut input = runne_domain::task_run::TaskRunInput::new(prompt)
        .map_err(|_| StoreCodecError::Truncated)?;
    if version >= 2 {
        match take_tag(bytes, pos)? {
            0 => {}
            1 => {
                let model = bounded_string(bytes, pos, 256, &mut 256)?;
                input = input
                    .with_requested_model(model)
                    .map_err(|_| StoreCodecError::Truncated)?;
            }
            tag => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TaskRun requested model",
                });
            }
        }
    }
    if version >= 3 {
        match take_tag(bytes, pos)? {
            0 => {}
            1 => {
                let profile_id = bounded_string(bytes, pos, 256, &mut 256)?;
                let digest_end = pos.checked_add(32).ok_or(StoreCodecError::Truncated)?;
                let digest = bytes
                    .get(*pos..digest_end)
                    .ok_or(StoreCodecError::Truncated)?
                    .try_into()
                    .map_err(|_| StoreCodecError::Truncated)?;
                *pos = digest_end;
                let profile =
                    runne_domain::task_run::SelectedProviderProfile::new(profile_id, digest)
                        .map_err(|_| StoreCodecError::Truncated)?;
                input = input
                    .with_selected_profile(profile)
                    .map_err(|_| StoreCodecError::Truncated)?;
            }
            tag => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TaskRun selected profile",
                });
            }
        }
    }
    if version >= 4 {
        match take_tag(bytes, pos)? {
            0 => {}
            1 => {
                let mut budget = runne_domain::task_run::MAX_LOCAL_COMMAND_BYTES;
                let executable = if version == 4 {
                    runne_domain::task_run::TaskRunExecutable::workspace_relative(bounded_string(
                        bytes,
                        pos,
                        4096,
                        &mut budget,
                    )?)
                } else {
                    let origin = take_tag(bytes, pos)?;
                    let value = bounded_string(bytes, pos, 4096, &mut budget)?;
                    match origin {
                        1 => runne_domain::task_run::TaskRunExecutable::workspace_relative(value),
                        2 => runne_domain::task_run::TaskRunExecutable::system_program(value),
                        tag => {
                            return Err(StoreCodecError::UnknownTag {
                                tag,
                                context: "TaskRun executable origin",
                            });
                        }
                    }
                }
                .map_err(|_| StoreCodecError::Truncated)?;
                let cwd = bounded_string(bytes, pos, 4096, &mut budget)?;
                let argc = read_u16_be(bytes, pos)? as usize;
                if argc == 0 || argc > runne_domain::task_run::MAX_LOCAL_COMMAND_ARGV {
                    return Err(StoreCodecError::Truncated);
                }
                let mut argv = Vec::with_capacity(argc);
                for _ in 0..argc {
                    argv.push(bounded_string(bytes, pos, 16 * 1024, &mut budget)?);
                }
                let envc = read_u16_be(bytes, pos)? as usize;
                if envc > runne_domain::task_run::MAX_LOCAL_COMMAND_ENV {
                    return Err(StoreCodecError::Truncated);
                }
                let mut env = Vec::with_capacity(envc);
                for _ in 0..envc {
                    env.push((
                        bounded_string(bytes, pos, 128, &mut budget)?,
                        bounded_string(bytes, pos, 16 * 1024, &mut budget)?,
                    ));
                }
                let command =
                    runne_domain::task_run::TaskRunLocalCommand::new(executable, cwd, argv, env)
                        .map_err(|_| StoreCodecError::Truncated)?;
                input = input
                    .with_local_command(command)
                    .map_err(|_| StoreCodecError::Truncated)?;
            }
            tag => {
                return Err(StoreCodecError::UnknownTag {
                    tag,
                    context: "TaskRun local command",
                });
            }
        }
    }
    Ok(TaskRunEvent::TaskRunSubmitted {
        conversation_id,
        workspace_id,
        input,
    })
}

fn take_tag(bytes: &[u8], pos: &mut usize) -> Result<u8, StoreCodecError> {
    let value = *bytes.get(*pos).ok_or(StoreCodecError::Truncated)?;
    *pos += 1;
    Ok(value)
}

fn bounded_string(
    bytes: &[u8],
    pos: &mut usize,
    limit: usize,
    budget: &mut usize,
) -> Result<String, StoreCodecError> {
    let value = read_len_prefixed(bytes, pos)?;
    if value.len() > limit || value.len() > *budget {
        return Err(StoreCodecError::Truncated);
    }
    *budget -= value.len();
    String::from_utf8(value.to_vec()).map_err(|_| StoreCodecError::Truncated)
}
