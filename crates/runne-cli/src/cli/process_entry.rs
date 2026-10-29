#[cfg(target_os = "linux")]
#[path = "chat_scope.rs"]
mod chat_scope;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    let arguments: Vec<OsString> = std::env::args_os().skip(1).collect();
    #[cfg(target_os = "linux")]
    if let Err(error) = chat_scope::ensure(&arguments) {
        write_process_outcome(&ProcessOutcome {
            stdout: String::new(),
            stderr: format!("{error}\n"),
            exit_code: 1,
        });
    }
    let outcome = run_entrypoint(arguments);
    write_process_outcome(&outcome);
}
