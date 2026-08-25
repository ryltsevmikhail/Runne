fn open_process(pid: u32, access: u32) -> Result<OwnedHandle, OwnerBoundProcessError> {
    let process = unsafe { OpenProcess(access, 0, pid) };
    (!process.is_null())
        .then(|| own(process))
        .ok_or(OwnerBoundProcessError::OwnershipMismatch)
}

fn process_identity(handle: HANDLE, pid: u32) -> Result<[u8; 32], OwnerBoundProcessError> {
    let mut creation = FILETIME::default();
    let mut exit = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    let valid =
        unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } != 0;
    if !valid {
        return Err(OwnerBoundProcessError::InvalidLaunchIdentity);
    }
    let mut digest = Sha256::new();
    digest.update(b"runne.windows-process-identity.v1");
    digest.update(pid.to_be_bytes());
    digest.update(creation.dwHighDateTime.to_be_bytes());
    digest.update(creation.dwLowDateTime.to_be_bytes());
    Ok(digest.finalize().into())
}

fn pipe_pair() -> Result<(HANDLE, HANDLE), OwnerBoundProcessError> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>())
            .map_err(|_| OwnerBoundProcessError::LifecycleRejected)?,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let created = unsafe { CreatePipe(&mut read, &mut write, &raw const attributes, 0) } != 0;
    if !created {
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    let non_inherit = unsafe { SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0) } != 0;
    if !non_inherit {
        close_raw(read);
        close_raw(write);
        return Err(OwnerBoundProcessError::LifecycleRejected);
    }
    Ok((read, write))
}

fn environment_block(
    request: &OwnerBoundProcessLaunchRequest<'_>,
) -> Result<Vec<u16>, OwnerBoundProcessError> {
    let mut entries = request.environment().iter().collect::<Vec<_>>();
    if entries.iter().any(|(key, value)| {
        key.is_empty()
            || key.contains(['=', '\0'])
            || value.contains('\0')
            || key.as_str() == LAUNCH_NONCE_ENV
    }) {
        return Err(OwnerBoundProcessError::PreparedInvocationInvalid);
    }
    entries.sort_by(|(left, _), (right, _)| {
        left.to_ascii_uppercase().cmp(&right.to_ascii_uppercase())
    });
    let mut block = Vec::new();
    for (key, value) in entries {
        block.extend(OsStr::new(key).encode_wide());
        block.push('=' as u16);
        block.extend(OsStr::new(value).encode_wide());
        block.push(0);
    }
    block.extend(
        OsStr::new(&format!(
            "{LAUNCH_NONCE_ENV}={}",
            hex::encode(request.launch_nonce())
        ))
        .encode_wide(),
    );
    block.extend([0, 0]);
    Ok(block)
}

fn command_line(executable: &Path, argv: &[String]) -> Result<Vec<u16>, OwnerBoundProcessError> {
    let mut value = quote_arg(
        executable
            .to_str()
            .ok_or(OwnerBoundProcessError::PreparedInvocationInvalid)?,
    );
    for arg in argv {
        if arg.contains('\0') {
            return Err(OwnerBoundProcessError::PreparedInvocationInvalid);
        }
        value.push(' ');
        value.push_str(&quote_arg(arg));
    }
    Ok(OsStr::new(&value).encode_wide().chain([0]).collect())
}

fn quote_arg(value: &str) -> String {
    let mut result = String::from('"');
    let mut slashes = 0;
    for character in value.chars() {
        if character == '\\' {
            slashes += 1;
        } else {
            result.extend(std::iter::repeat_n(
                '\\',
                slashes * if character == '"' { 2 } else { 1 },
            ));
            if character == '"' {
                result.push('\\');
            }
            result.push(character);
            slashes = 0;
        }
    }
    result.extend(std::iter::repeat_n('\\', slashes * 2));
    result.push('"');
    result
}

fn wide_path(path: &Path) -> Result<Vec<u16>, OwnerBoundProcessError> {
    path.to_str()
        .filter(|value| !value.contains('\0'))
        .map(|value| OsStr::new(value).encode_wide().chain([0]).collect())
        .ok_or(OwnerBoundProcessError::PreparedInvocationInvalid)
}

fn wide_name(nonce: &[u8; 16]) -> Vec<u16> {
    OsStr::new(&format!(r"Local\runne-process-{}", hex::encode(nonce)))
        .encode_wide()
        .chain([0])
        .collect()
}

fn own(handle: HANDLE) -> OwnedHandle {
    unsafe { OwnedHandle::from_raw_handle(handle as _) }
}

fn close_raw(handle: HANDLE) {
    if !handle.is_null() {
        unsafe { CloseHandle(handle) };
    }
}

fn terminate_raw(handle: HANDLE) {
    let _ = unsafe { windows_sys::Win32::System::Threading::TerminateProcess(handle, 1) };
}

fn spawn_reader(reader: Option<File>, stderr: bool, output: Arc<Mutex<Vec<CapturedOutput>>>) {
    let Some(mut reader) = reader else { return };
    let _ = std::thread::Builder::new()
        .name("runne-process-output".into())
        .spawn(move || {
            let mut buffer = vec![0_u8; 64 * 1024];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let Ok(mut captured) = output.lock() else {
                    break;
                };
                let used = captured
                    .iter()
                    .map(|chunk| chunk.bytes.len())
                    .sum::<usize>();
                if used >= MAX_CAPTURE_BYTES {
                    break;
                }
                let take = read.min(MAX_CAPTURE_BYTES - used);
                captured.push(CapturedOutput {
                    stderr,
                    bytes: buffer[..take].to_vec(),
                });
            }
        });
}

#[cfg(test)]
mod tests {
    use super::{command_line, quote_arg};
    use std::path::Path;

    #[test]
    fn quotes_windows_arguments_without_shell_expansion() {
        assert_eq!(quote_arg(r#"plain"#), r#""plain""#);
        assert_eq!(quote_arg(r#"with space"#), r#""with space""#);
        assert_eq!(quote_arg(r#"quote"mark"#), r#""quote\"mark""#);
        assert_eq!(quote_arg(r#"trailing\"#), r#""trailing\\""#);
    }

    #[test]
    fn command_line_keeps_executable_and_each_argument_quoted() {
        let command = command_line(
            Path::new(r#"C:\Program Files\Runne\tool.exe"#),
            &[r#"--name=one two"#.into(), r#"quote"mark"#.into()],
        )
        .expect("command line");
        let command = String::from_utf16(&command[..command.len() - 1]).expect("UTF-16");
        assert_eq!(
            command,
            r#""C:\Program Files\Runne\tool.exe" "--name=one two" "quote\"mark""#
        );
    }
}
