#![forbid(unsafe_code)]

mod coordinator;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod application;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod root_bridge;

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() -> std::process::ExitCode {
    if std::env::args_os().len() != 1 || application::run().is_err() {
        return std::process::ExitCode::FAILURE;
    }
    std::process::ExitCode::SUCCESS
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
const fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
