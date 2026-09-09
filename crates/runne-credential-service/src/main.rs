#[cfg(any(test, target_os = "macos"))]
mod keychain;
#[cfg(any(test, target_os = "macos"))]
mod listeners;
#[cfg(any(test, target_os = "macos"))]
mod package_identity;
#[cfg(any(test, target_os = "macos"))]
mod service_backend;

#[cfg(target_os = "macos")]
fn main() -> std::process::ExitCode {
    listeners::run()
}

#[cfg(not(target_os = "macos"))]
const fn main() -> std::process::ExitCode {
    std::process::ExitCode::FAILURE
}
