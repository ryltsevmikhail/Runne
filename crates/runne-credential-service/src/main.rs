mod keychain;
mod listeners;
mod package_identity;
mod service_backend;

fn main() -> std::process::ExitCode {
    listeners::run()
}
