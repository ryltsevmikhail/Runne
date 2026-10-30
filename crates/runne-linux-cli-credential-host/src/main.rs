#[cfg(target_os = "linux")]
mod enrollment;
#[cfg(target_os = "linux")]
mod measurements;
#[cfg(target_os = "linux")]
mod session;
#[cfg(target_os = "linux")]
mod tty;
#[cfg(target_os = "linux")]
use policy::{HostResult, ImagePolicy};
#[cfg(target_os = "linux")]
use runne_daemon::linux_cli_credential_host::policy;

fn main() {
    #[cfg(target_os = "linux")]
    {
        let args: Vec<_> = std::env::args_os().skip(1).collect();
        if args.len() == 4 && args[0] == "deepseek" && args[1] == "upgrade" {
            let result = session::terminal().and_then(|_| {
                runne_daemon::linux_cli_credential_host::upgrade::upgrade(
                    std::path::Path::new(&args[2]),
                    std::path::Path::new(&args[3]),
                )
            });
            match result {
                Ok(()) => println!(
                    "Installation authority transition confirmed. No provider request was sent."
                ),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
            return;
        }
        if args != ["deepseek", "pair"] {
            eprintln!("Usage: runne-credential-host deepseek pair");
            std::process::exit(2);
        }
        if let Err(error) = run("pair") {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("Linux credential host is unavailable on this platform");
        std::process::exit(1);
    }
}

#[cfg(target_os = "linux")]
/// Enrolls DeepSeek from the foreground owner terminal while the daemon is stopped.
fn run(action: &str) -> HostResult<()> {
    if action != "pair" {
        return Err("unsupported credential host action");
    }
    let mut terminal = session::terminal()?;
    let config = runne_daemon::config::load_external_config()
        .map_err(|_| "credential host configuration unavailable")?;
    let policy = std::sync::Arc::new(ImagePolicy::load(&config)?);
    let bootstrap = runne_daemon::bootstrap::bootstrap(&config)
        .map_err(|_| "runtime unavailable; stop its daemon before enrollment")?;
    use std::io::Write;
    terminal.write_all(b"Store a DeepSeek key for this standalone Runne runtime. No API request will be sent.\n")
        .map_err(|_| "terminal unavailable")?;
    let secret = tty::read_secret(&mut terminal).map_err(|error| match error {
        tty::InputError::Cancelled => "credential entry cancelled; no key was stored",
        tty::InputError::TimedOut => "credential entry timed out; no key was stored",
        tty::InputError::Invalid => "invalid credential input; no key was stored",
        tty::InputError::Unavailable => "credential terminal unavailable; no key was stored",
    })?;
    let material = runne_secure_store::ProviderCredentialMaterial::new(secret.to_vec())
        .map_err(|_| "invalid credential")?;
    drop(secret);
    enrollment::pair(bootstrap, policy, material)?;
    terminal
        .write_all(b"DeepSeek credential stored and local readback confirmed.\n")
        .map_err(|_| "credential stored; terminal output unavailable")?;
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod test_policy;
