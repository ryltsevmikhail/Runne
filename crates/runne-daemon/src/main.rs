//! Runne Runtime Daemon.

use std::ffi::OsString;

use runne_daemon::application::DaemonApplication;
use runne_daemon::doctor::{format_report, format_report_json, run_doctor};
#[cfg(any(unix, windows))]
use runne_daemon::protected_activation::{
    ProtectedActivationChannel, run_verified_protected_channel,
};

const DAEMON_HELP: &str = "\
Runne runtime daemon.

Usage:
  runned            Start the daemon (canonical runtime)
  runned doctor     Show provider readiness diagnostics without bootstrapping
  runned --help     Show this help
  runned --version  Show version information

`doctor` runs without a credential and never prints secrets. It reports the
active provider, selected profile/model, and per-provider credential status.

Doctor exit codes:
  0  Execution-ready (deterministic mode or active provider credential configured)
  1  Active provider credential missing/denied, backend unsupported, or config unreadable
";

/// Parsed first-process decision: diagnostics never bootstrap the daemon.
enum Invocation {
    Run,
    Help,
    Version,
    Doctor { json: bool },
    Invalid(String),
}

/// Parses daemon arguments without echoing argument values into errors
/// (arguments may accidentally contain secret material).
fn parse_invocation(arguments: &[OsString]) -> Invocation {
    match arguments {
        [] => Invocation::Run,
        [one] => match one.to_str() {
            Some("-h" | "--help") => Invocation::Help,
            Some("-V" | "--version") => Invocation::Version,
            Some("doctor") => Invocation::Doctor { json: false },
            Some(_) | None => {
                Invocation::Invalid("unknown argument (run 'runned --help' for usage)".to_owned())
            }
        },
        [one, two, three] if one.to_str() == Some("doctor") && two.to_str() == Some("--format") => {
            match three.to_str() {
                Some("json") => Invocation::Doctor { json: true },
                Some("text") => Invocation::Doctor { json: false },
                _ => Invocation::Invalid(
                    "unknown doctor format (run 'runned --help' for usage)".to_owned(),
                ),
            }
        }
        [one, two] if one.to_str() == Some("doctor") => {
            match two
                .to_str()
                .and_then(|value| value.strip_prefix("--format="))
            {
                Some("json") => Invocation::Doctor { json: true },
                Some("text") => Invocation::Doctor { json: false },
                _ => Invocation::Invalid(
                    "unknown doctor format (run 'runned --help' for usage)".to_owned(),
                ),
            }
        }
        [_, ..] => Invocation::Invalid(
            "unexpected extra arguments (run 'runned --help' for usage)".to_owned(),
        ),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    #[cfg(all(target_os = "macos", feature = "persistent-reference-probe"))]
    if persistent_reference_probe::selected(&arguments) {
        return persistent_reference_probe::run().map_err(|_| "persistent-reference-probe".into());
    }
    match parse_invocation(&arguments) {
        Invocation::Run => {}
        Invocation::Help => {
            print!("{DAEMON_HELP}");
            return Ok(());
        }
        Invocation::Version => {
            println!("runned {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Invocation::Doctor { json } => {
            let report = run_doctor();
            let rendered = if json {
                format_report_json(&report)
            } else {
                format_report(&report)
            };
            println!("{rendered}");
            if !report.execution_ready() {
                std::process::exit(1);
            }
            return Ok(());
        }
        Invocation::Invalid(message) => {
            eprintln!("error: {message}");
            std::process::exit(2);
        }
    }

    tracing_subscriber::fmt::init();

    #[cfg(any(unix, windows))]
    match ProtectedActivationChannel::from_inherited_stdin() {
        Ok(Some(channel)) => {
            if run_protected(channel).is_err() {
                eprintln!("fatal: protected activation failed");
                std::process::exit(2);
            }
            return Ok(());
        }
        Ok(None) => {}
        Err(_) => {
            eprintln!("fatal: protected activation channel failed");
            std::process::exit(2);
        }
    }

    run_external()
}

fn run_external() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let application = DaemonApplication::start_external_from_fixed_source()
            .await
            .map_err(|error| {
                eprintln!("fatal: bootstrap error: {error}");
                std::process::exit(2);
            })?;
        tracing::info!(
            authority_id = hex::encode(application.authority_id()),
            db_existed = application.db_existed(),
            bind = %application.local_addr()?,
            "bootstrap complete, canonical runtime ready"
        );
        tracing::info!("daemon ready, press Ctrl+C to stop");

        application
            .run(async { tokio::signal::ctrl_c().await.map_err(Into::into) })
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;

    Ok(())
}

#[cfg(any(unix, windows))]
fn run_protected(
    channel: ProtectedActivationChannel,
) -> Result<(), runne_daemon::error::DaemonError> {
    run_verified_protected_channel(channel)
}

#[cfg(all(target_os = "macos", feature = "persistent-reference-probe"))]
pub mod persistent_reference_probe;
