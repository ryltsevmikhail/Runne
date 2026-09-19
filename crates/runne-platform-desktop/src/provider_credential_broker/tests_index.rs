use super::*;

#[path = "tests.rs"]
mod core;
#[cfg(unix)]
#[path = "tests_daemon_evidence.rs"]
mod tests_daemon_evidence;
#[cfg(unix)]
#[path = "tests_daemon_rendezvous.rs"]
mod tests_daemon_rendezvous;
#[path = "tests_macos_descriptor_gate.rs"]
mod tests_macos_descriptor_gate;
#[cfg(target_os = "macos")]
#[path = "tests_macos_secret_slot.rs"]
mod tests_macos_secret_slot;
#[path = "tests_macos_writer_admission.rs"]
mod tests_macos_writer_admission;
#[cfg(unix)]
#[path = "tests_prepared_daemon_rendezvous.rs"]
mod tests_prepared_daemon_rendezvous;
#[cfg(unix)]
#[path = "tests_protocol_tags.rs"]
mod tests_protocol_tags;
#[path = "tests_unix_descriptor.rs"]
mod tests_unix_descriptor;
