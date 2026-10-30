//! Strict argument parsing for the sandbox helper.

use std::ffi::OsString;
use std::os::fd::RawFd;
use std::path::Path;

use runne_sandbox_protocol::STATUS_FD_FLAG;

/// Largest profile the helper accepts from the runtime.
pub const MAX_PROFILE_BYTES: usize = 64 * 1024;

/// One validated helper invocation.
pub enum Invocation {
    /// Run the built-in sandbox self-test.
    SelfTest,
    /// Apply a profile and replace this process with the requested program.
    Launch(Launch),
}

/// Validated launch request.
pub struct Launch {
    /// Read end of the profile descriptor inherited from the runtime.
    pub profile_fd: RawFd,
    /// Optional directory descriptor used as the child working directory.
    pub cwd_fd: Option<RawFd>,
    /// Absolute program path.
    pub program: OsString,
    /// Program arguments, excluding `argv[0]`.
    pub args: Vec<OsString>,
}

/// Parses helper arguments, excluding `argv[0]`.
///
/// # Errors
/// Returns a diagnostic when a flag is unknown or duplicated, when a descriptor
/// value is not a non-negative integer, or when the program path is relative.
pub fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Invocation, String> {
    let mut remaining = args.into_iter();
    let Some(first) = remaining.next() else {
        return Err("missing arguments".to_string());
    };
    if first == "--self-test" {
        if remaining.next().is_some() {
            return Err("--self-test takes no arguments".to_string());
        }
        return Ok(Invocation::SelfTest);
    }

    let mut profile_fd = None;
    let mut cwd_fd = None;
    let mut status_fd = None;
    let mut rest = Vec::new();
    let mut arguments = std::iter::once(first).chain(remaining);
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            rest.extend(arguments);
            break;
        } else if argument == STATUS_FD_FLAG {
            if status_fd.is_some() {
                return Err(format!("duplicate {STATUS_FD_FLAG}"));
            }
            status_fd = Some(parse_fd(arguments.next(), STATUS_FD_FLAG)?);
        } else if argument == "--profile-fd" {
            if profile_fd.is_some() {
                return Err("duplicate --profile-fd".to_string());
            }
            profile_fd = Some(parse_fd(arguments.next(), "--profile-fd")?);
        } else if argument == "--cwd-fd" {
            if cwd_fd.is_some() {
                return Err("duplicate --cwd-fd".to_string());
            }
            cwd_fd = Some(parse_fd(arguments.next(), "--cwd-fd")?);
        } else {
            return Err(format!("unknown argument: {}", argument.to_string_lossy()));
        }
    }

    let profile_fd = profile_fd.ok_or_else(|| "--profile-fd is required".to_string())?;
    let mut rest = rest.into_iter();
    let program = rest
        .next()
        .ok_or_else(|| "missing program after --".to_string())?;
    if !Path::new(&program).is_absolute() {
        return Err("program must be an absolute path".to_string());
    }
    Ok(Invocation::Launch(Launch {
        profile_fd,
        cwd_fd,
        program,
        args: rest.collect(),
    }))
}

fn parse_fd(value: Option<OsString>, flag: &str) -> Result<RawFd, String> {
    let value = value.ok_or_else(|| format!("{flag} requires a value"))?;
    let text = value
        .to_str()
        .ok_or_else(|| format!("{flag} must be ASCII"))?;
    let fd: RawFd = text
        .parse()
        .map_err(|_| format!("{flag} must be a non-negative integer"))?;
    if fd < 3 {
        return Err(format!("{flag} must be at least 3"));
    }
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(arguments: &[&str]) -> Result<Invocation, String> {
        parse(arguments.iter().map(OsString::from))
    }

    #[test]
    fn accepts_a_self_test() {
        assert!(matches!(
            parse_str(&["--self-test"]),
            Ok(Invocation::SelfTest)
        ));
    }

    #[test]
    fn accepts_a_profile_and_program() {
        let Ok(Invocation::Launch(launch)) = parse_str(&[
            "--profile-fd",
            "3",
            "--cwd-fd",
            "4",
            "--",
            "/bin/echo",
            "hello",
        ]) else {
            panic!("expected a launch invocation");
        };
        assert_eq!(launch.profile_fd, 3);
        assert_eq!(launch.cwd_fd, Some(4));
        assert_eq!(launch.program, OsString::from("/bin/echo"));
        assert_eq!(launch.args, vec![OsString::from("hello")]);
    }

    #[test]
    fn rejects_a_relative_program() {
        assert!(parse_str(&["--profile-fd", "3", "--", "echo"]).is_err());
    }

    #[test]
    fn accepts_a_status_descriptor() {
        let Ok(Invocation::Launch(launch)) =
            parse_str(&[STATUS_FD_FLAG, "5", "--profile-fd", "3", "--", "/bin/echo"])
        else {
            panic!("expected a launch invocation");
        };
        assert_eq!(launch.profile_fd, 3);
    }

    #[test]
    fn rejects_a_duplicate_status_descriptor() {
        assert!(
            parse_str(&[
                STATUS_FD_FLAG,
                "5",
                STATUS_FD_FLAG,
                "6",
                "--profile-fd",
                "3",
                "--",
                "/bin/echo",
            ])
            .is_err()
        );
    }

    #[test]
    fn rejects_a_stdio_status_descriptor() {
        assert!(parse_str(&[STATUS_FD_FLAG, "2", "--profile-fd", "3", "--", "/bin/echo"]).is_err());
    }

    #[test]
    fn rejects_the_standard_descriptors() {
        assert!(parse_str(&["--profile-fd", "2", "--", "/bin/echo"]).is_err());
    }

    #[test]
    fn rejects_duplicate_flags() {
        assert!(parse_str(&["--profile-fd", "3", "--profile-fd", "4", "--", "/bin/echo"]).is_err());
    }

    #[test]
    fn rejects_unknown_arguments() {
        assert!(parse_str(&["--allow-everything", "--", "/bin/echo"]).is_err());
    }
}
