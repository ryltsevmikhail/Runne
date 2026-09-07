//! Process entry: env_clear, inherited private IPC only, no shell, no
//! ambient listeners. The real binary wiring (secret/socket inheritance)
//! lands with Task 7's supervisor; this entry stays minimal and offline.
fn main() {
    // Non-authoritative diagnostics only.
    eprintln!("runne-inference-host: launched out of band; exiting");
}
