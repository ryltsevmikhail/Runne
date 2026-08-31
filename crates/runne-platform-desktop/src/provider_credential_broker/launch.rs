use std::process::{Command, Stdio};

use runne_platform_ports::provider_credential_broker::VerifiedWriterLaunchSpec;

/// Builds the only permitted direct child command for a credential writer.
///
/// Transport adapters attach their authenticated inherited descriptors after
/// this construction. They cannot add argv or environment capability values.
#[must_use]
pub fn writer_command(spec: &VerifiedWriterLaunchSpec) -> Command {
    let mut command = Command::new(spec.executable());
    command
        .env_clear()
        .env_remove("PATH")
        .args(spec.arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
}
