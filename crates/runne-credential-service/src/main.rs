mod keychain;
mod listeners;

fn main() -> std::process::ExitCode {
    listeners::run()
}
