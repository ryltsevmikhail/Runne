mod keychain;
mod listeners;
mod package_identity;
mod service_backend;

#[cfg(test)]
mod secret_lifetime_tests;

fn main() -> std::process::ExitCode {
    listeners::run()
}
