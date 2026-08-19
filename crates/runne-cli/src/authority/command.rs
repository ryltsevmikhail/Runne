//! Closed authority command parser; lifecycle implementations intentionally do not live here.

use std::collections::VecDeque;
use std::ffi::OsString;

use super::super::CliError;
use super::{
    adapter::{SystemAuthorityFiles, SystemAuthorityGit},
    lifecycle::{
        AuthorityClock, AuthorityCommandRunner, AuthorityGitResolver, AuthorityRng, AuthorityTty,
        VerifyRequest,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
enum AuthorityCommand {
    Init {
        trust_out: String,
    },
    Sign {
        trust_config: String,
        receipt_out: String,
    },
    Verify {
        trust_config: String,
        receipt: String,
        anchor_epoch: u64,
        anchor_trust_sha256: [u8; 32],
    },
    Rotate {
        trust_config: String,
        rotation_out: String,
        successor_trust_out: String,
    },
    Backup {
        trust_config: String,
        output: String,
    },
    Restore {
        trust_config: String,
        input: String,
        replace_active_trust: Option<String>,
        replace_active_key_id: Option<[u8; 32]>,
    },
    TrustReset {
        trust_config: String,
        acknowledgement: String,
    },
}

pub(super) fn run(mut arguments: VecDeque<OsString>) -> Result<String, CliError> {
    if arguments.pop_front().as_deref() != Some(std::ffi::OsStr::new("authority")) {
        return Err(CliError::AuthorityUsage);
    }
    if arguments
        .front()
        .is_some_and(|argument| argument == "--help")
    {
        arguments.pop_front();
        return if arguments.is_empty() {
            Ok("authority: init sign verify rotate backup restore trust-reset (no --yes)".into())
        } else {
            Err(CliError::AuthorityUsage)
        };
    }
    execute_transport(parse(&mut arguments)?)
}

fn parse(arguments: &mut VecDeque<OsString>) -> Result<AuthorityCommand, CliError> {
    let command = arguments.pop_front().ok_or(CliError::AuthorityUsage)?;
    let command = command
        .into_string()
        .map_err(|_| CliError::AuthorityUsage)?;
    let parsed = match command.as_str() {
        "init" => AuthorityCommand::Init {
            trust_out: value(arguments, "--trust-out")?,
        },
        "sign" => AuthorityCommand::Sign {
            trust_config: value(arguments, "--trust-config")?,
            receipt_out: value(arguments, "--receipt-out")?,
        },
        "verify" => parse_verify(arguments)?,
        "rotate" => AuthorityCommand::Rotate {
            trust_config: value(arguments, "--trust-config")?,
            rotation_out: value(arguments, "--rotation-out")?,
            successor_trust_out: value(arguments, "--successor-trust-out")?,
        },
        "backup" => AuthorityCommand::Backup {
            trust_config: value(arguments, "--trust-config")?,
            output: value(arguments, "--output")?,
        },
        "restore" => parse_restore(arguments)?,
        "trust-reset" => AuthorityCommand::TrustReset {
            trust_config: value(arguments, "--trust-config")?,
            acknowledgement: value(arguments, "--ack-compromise")?,
        },
        _ => return Err(CliError::AuthorityUsage),
    };
    if arguments.is_empty() {
        Ok(parsed)
    } else {
        Err(CliError::AuthorityUsage)
    }
}

fn value(arguments: &mut VecDeque<OsString>, expected: &str) -> Result<String, CliError> {
    if arguments.pop_front().as_deref() != Some(std::ffi::OsStr::new(expected)) {
        return Err(CliError::AuthorityUsage);
    }
    let value = arguments
        .pop_front()
        .ok_or(CliError::AuthorityUsage)?
        .into_string()
        .map_err(|_| CliError::AuthorityUsage)?;
    if value.is_empty() || value == "--yes" {
        Err(CliError::AuthorityUsage)
    } else {
        Ok(value)
    }
}

fn parse_verify(arguments: &mut VecDeque<OsString>) -> Result<AuthorityCommand, CliError> {
    let trust_config = value(arguments, "--trust-config")?;
    let receipt = value(arguments, "--receipt")?;
    let epoch = value(arguments, "--anchor-epoch")?;
    let anchor_epoch = epoch
        .bytes()
        .all(|byte| byte.is_ascii_digit())
        .then(|| epoch.parse::<u64>().ok())
        .flatten()
        .filter(|epoch| *epoch != 0)
        .ok_or(CliError::AuthorityUsage)?;
    let anchor_trust_sha256 = parse_lower_hex_32(&value(arguments, "--anchor-trust-sha256")?)?;
    Ok(AuthorityCommand::Verify {
        trust_config,
        receipt,
        anchor_epoch,
        anchor_trust_sha256,
    })
}

fn parse_restore(arguments: &mut VecDeque<OsString>) -> Result<AuthorityCommand, CliError> {
    let trust_config = value(arguments, "--trust-config")?;
    let input = value(arguments, "--input")?;
    let (replace_active_trust, replace_active_key_id) = if arguments.is_empty() {
        (None, None)
    } else {
        let trust = value(arguments, "--replace-active-trust")?;
        let key_id = parse_lower_hex_32(&value(arguments, "--replace-active-key-id")?)?;
        (Some(trust), Some(key_id))
    };
    Ok(AuthorityCommand::Restore {
        trust_config,
        input,
        replace_active_trust,
        replace_active_key_id,
    })
}

fn parse_lower_hex_32(value: &str) -> Result<[u8; 32], CliError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase() && byte <= b'f')
    {
        return Err(CliError::AuthorityUsage);
    }
    let mut output = [0; 32];
    for (slot, source) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(
            std::str::from_utf8(source).map_err(|_| CliError::AuthorityUsage)?,
            16,
        )
        .map_err(|_| CliError::AuthorityUsage)?;
    }
    Ok(output)
}

fn execute_transport(command: AuthorityCommand) -> Result<String, CliError> {
    if let AuthorityCommand::Verify {
        trust_config,
        receipt,
        anchor_epoch,
        anchor_trust_sha256,
    } = command
    {
        return execute_verify(&VerifyRequest {
            trust_config,
            receipt,
            anchor_epoch,
            anchor_trust_sha256,
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = command;
        Err(CliError::AuthorityUnsupportedPlatform)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = command;
        // No safe hidden-input facility exists in the current dependency set. Do not fall back
        // to visible stdin or attempt terminal mode changes outside a reviewed TTY adapter.
        Err(CliError::AuthorityUnavailable)
    }
}

fn execute_verify(request: &VerifyRequest) -> Result<String, CliError> {
    let git = SystemAuthorityGit::open()?;
    let files = SystemAuthorityFiles::new(git.repository_root().to_path_buf());
    let mut rng = NoopRng;
    let output =
        AuthorityCommandRunner::new(&(), &git, &UnavailableTty, &mut rng, &NoopClock, &files)
            .verify(request)?;
    String::from_utf8(output.stdout).map_err(|_| CliError::AuthorityUnavailable)
}

struct NoopRng;
impl AuthorityRng for NoopRng {}

struct NoopClock;
impl AuthorityClock for NoopClock {
    #[cfg(any(test, target_os = "macos"))]
    fn utc_rfc3339_seconds(&self) -> Result<String, CliError> {
        Err(CliError::AuthorityUnavailable)
    }
}

struct UnavailableTty;
impl AuthorityTty for UnavailableTty {
    #[cfg(any(test, target_os = "macos"))]
    fn confirm(&self, _: &str, _: &str) -> Result<(), CliError> {
        Err(CliError::AuthorityUnavailable)
    }
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;
    #[test]
    fn parser_has_only_the_seven_closed_commands() {
        assert!(matches!(
            parse(&mut VecDeque::from([
                OsString::from("sign"),
                OsString::from("--trust-config"),
                OsString::from("trust"),
                OsString::from("--receipt-out"),
                OsString::from("receipt")
            ])),
            Ok(AuthorityCommand::Sign { .. })
        ));
        assert!(matches!(
            parse(&mut VecDeque::from([OsString::from("unknown")])),
            Err(CliError::AuthorityUsage)
        ));
        assert!(matches!(
            parse(&mut VecDeque::from([
                OsString::from("sign"),
                OsString::from("--yes")
            ])),
            Err(CliError::AuthorityUsage)
        ));
    }

    #[test]
    fn parser_requires_explicit_verify_anchor_and_paired_restore_replacement() {
        let verify = parse(&mut VecDeque::from([
            OsString::from("verify"),
            OsString::from("--trust-config"),
            OsString::from("docs/trust.json"),
            OsString::from("--receipt"),
            OsString::from("docs/evidence/receipt.json"),
            OsString::from("--anchor-epoch"),
            OsString::from("4"),
            OsString::from("--anchor-trust-sha256"),
            OsString::from("a".repeat(64)),
        ]));
        assert!(matches!(
            verify,
            Ok(AuthorityCommand::Verify {
                anchor_epoch: 4,
                ..
            })
        ));
        let restore = parse(&mut VecDeque::from([
            OsString::from("restore"),
            OsString::from("--trust-config"),
            OsString::from("docs/trust.json"),
            OsString::from("--input"),
            OsString::from("/tmp/backup.json"),
            OsString::from("--replace-active-trust"),
            OsString::from("docs/current.json"),
        ]));
        assert!(matches!(restore, Err(CliError::AuthorityUsage)));
    }
}
