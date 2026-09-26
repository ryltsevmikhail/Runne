struct LinuxEnrollmentPeerIdentity {
    authority: [u8; 16],
    desktop: [u8; 16],
    session: [u8; 16],
    daemon: [u8; 16],
    generation: u64,
}

fn linux_process_start_ticks(pid: u32) -> Result<u64, ProtectedBundledRuntimeError> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|_| ProtectedBundledRuntimeError::OwnershipMismatch)?;
    stat.rsplit_once(')')
        .and_then(|(_, fields)| fields.split_whitespace().nth(19))
        .and_then(|value| value.parse().ok())
        .filter(|value| *value != 0)
        .ok_or(ProtectedBundledRuntimeError::OwnershipMismatch)
}
