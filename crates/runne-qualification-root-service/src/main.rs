#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
mod authority;
#[cfg(target_os = "macos")]
mod executable;
#[cfg(target_os = "macos")]
mod issue_input;
#[cfg(target_os = "macos")]
mod issuer;
#[cfg(target_os = "macos")]
mod protected_file;
#[cfg(target_os = "macos")]
mod session_factory;
#[cfg(target_os = "macos")]
mod startup;
#[cfg(target_os = "macos")]
mod state;
#[cfg(all(test, target_os = "macos"))]
mod tests;

#[derive(Clone, Copy, Debug)]
struct Error;
type Result<T> = std::result::Result<T, Error>;

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 || startup::run().is_err() {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(target_os = "macos"))]
const fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
