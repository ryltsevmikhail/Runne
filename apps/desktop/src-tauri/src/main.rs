fn main() {
    let mut arguments: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    if arguments
        .first()
        .is_some_and(|argument| argument == "--chat")
    {
        arguments.remove(0);
        arguments.insert(0, std::ffi::OsString::from("chat"));
        let outcome = runne_cli::tui_backend::entry(arguments);
        runne_cli::write_process_outcome(&outcome);
    }
    runne_desktop::run();
}
