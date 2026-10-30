#[expect(
    clippy::future_not_send,
    reason = "the CLI runs its command tree inline with the current-thread runtime"
)]
async fn run_after_broker_bootstrap(
    arguments: Vec<OsString>,
) -> (Result<CommandOutput, CliError>, OutputFormat) {
    match parse_global_options(arguments) {
        Ok(state) => {
            let format = state.format;
            let (outcome, cleanup) =
                runne_runtime_client::with_local_session_cleanup(run(state.arguments, format))
                    .await;
            if cleanup.is_err() {
                eprintln!("warning: local session cleanup failed; command outcome is unchanged");
            }
            (outcome, format)
        }
        Err(error) => (Err(error), OutputFormat::Text),
    }
}
