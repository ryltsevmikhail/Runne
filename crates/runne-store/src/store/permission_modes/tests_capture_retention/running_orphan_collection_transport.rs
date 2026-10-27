//! Dedicated final S publication; same bounded socket pump and actual ownership.
use super::{
    collection_phase,
    collection_response::{self, INPUT_CAP},
    context::CaseContext,
    record_pump::{self, Failure, Sockets},
};
use std::{
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    process::{Command, ExitStatus, Stdio},
};

fn pair(parent_reads: bool) -> Result<(UnixStream, Stdio), Failure> {
    let (parent, child) = UnixStream::pair().map_err(|_| Failure::before_spawn("socket pair"))?;
    parent
        .set_nonblocking(true)
        .map_err(|_| Failure::before_spawn("nonblocking parent"))?;
    parent
        .shutdown(if parent_reads {
            Shutdown::Write
        } else {
            Shutdown::Read
        })
        .map_err(|_| Failure::before_spawn("parent unused direction"))?;
    child
        .shutdown(if parent_reads {
            Shutdown::Read
        } else {
            Shutdown::Write
        })
        .map_err(|_| Failure::before_spawn("child unused direction"))?;
    let fd: OwnedFd = child.into();
    Ok((parent, Stdio::from(fd)))
}

pub(super) fn publish(context: &CaseContext, line: &str) -> Result<ExitStatus, Failure> {
    if !(1..=INPUT_CAP).contains(&line.len())
        || !line.ends_with('\n')
        || !line.bytes().all(|b| b == b'\n' || (32..=126).contains(&b))
    {
        return Err(Failure::before_spawn("bounded canonical collector input"));
    }
    // No helper exists yet; all phase assertions run before spawn.
    collection_phase::check(context, None);
    let (input_parent, input_child) = pair(false)?;
    let (output_parent, output_child) = pair(true)?;
    let (error_parent, error_child) = pair(true)?;
    let mut command = Command::new("/collection-helper");
    command
        .env_clear()
        .args([
            "publish".to_owned(),
            "provisional".to_owned(),
            context.record.collection_root.clone(),
            context.collection_root.identity.device.to_string(),
            context.collection_root.identity.inode.to_string(),
            context.deadline.0.to_string(),
            std::process::id().to_string(),
        ])
        .stdin(input_child)
        .stdout(output_child)
        .stderr(error_child);
    context
        .deadline
        .try_remaining()
        .map_err(Failure::before_spawn)?;
    let result = command.spawn();
    drop(command);
    let child = result.map_err(|_| Failure::before_spawn("collection helper spawn"))?;
    let sockets = Sockets {
        input: input_parent,
        output: output_parent,
        errors: error_parent,
    };
    let (frame, status) = record_pump::run(child, sockets, line.as_bytes(), context.deadline)?;
    collection_response::decode(&frame, line.len())
        .map_err(|code| Failure::collected(code, status))?;
    collection_phase::after_collection(context, status, line.len())?;
    // Actual helper collected0, both EOFs, exact frame, empty stderr and D.
    // C must still observe real S0 and perform its own read/adoption/cleanup.
    Ok(status)
}
