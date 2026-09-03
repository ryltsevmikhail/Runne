mod keychain;
mod listeners;
mod package_identity;

fn main() -> std::process::ExitCode {
    listeners::run()
}
