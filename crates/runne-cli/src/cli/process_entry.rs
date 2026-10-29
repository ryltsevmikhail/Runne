fn main() {
    let arguments = std::env::args_os().skip(1).collect();
    let outcome = run_entrypoint(arguments);
    write_process_outcome(&outcome);
}
