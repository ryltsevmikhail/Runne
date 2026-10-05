use super::LinuxCommandError;
use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;

pub(super) fn encode_vectors(
    argv: &[OsString],
    env: &[(OsString, OsString)],
) -> Result<(Vec<CString>, Vec<CString>), LinuxCommandError> {
    if argv.is_empty() || argv.len() > 256 || env.len() > 256 {
        return Err(LinuxCommandError::Invalid);
    }
    let mut args = Vec::with_capacity(argv.len());
    for item in argv {
        let value = CString::new(item.as_bytes()).map_err(|_| LinuxCommandError::Invalid)?;
        if value.as_bytes().len() > 16 * 1024 {
            return Err(LinuxCommandError::Invalid);
        }
        args.push(value);
    }
    let mut vars = Vec::with_capacity(env.len());
    for (key, value) in env {
        if key.is_empty() || key.as_bytes().contains(&b'=') {
            return Err(LinuxCommandError::Invalid);
        }
        let mut bytes = key.as_bytes().to_vec();
        bytes.push(b'=');
        bytes.extend_from_slice(value.as_bytes());
        let value = CString::new(bytes).map_err(|_| LinuxCommandError::Invalid)?;
        if value.as_bytes().len() > 16 * 1024 {
            return Err(LinuxCommandError::Invalid);
        }
        vars.push(value);
    }
    if args
        .iter()
        .chain(vars.iter())
        .map(|item| item.as_bytes().len())
        .sum::<usize>()
        > 128 * 1024
    {
        return Err(LinuxCommandError::Invalid);
    }
    Ok((args, vars))
}
