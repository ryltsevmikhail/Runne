//! Guest-only fixed executable; never a native permission launch or PATH search.
use super::context::CaseContext;
use super::record_protocol::{self, Name, Operation, RECORD_CAP};
use super::record_pump::{self, Failure, Sockets};
use super::record_validation;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitStatus, Stdio};

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

pub(super) fn call(
    context: &CaseContext,
    operation: Operation,
    name: Name,
    input: &[u8],
) -> Result<(Vec<u8>, ExitStatus), Failure> {
    if (operation == Operation::Publish && !(1..=RECORD_CAP).contains(&input.len()))
        || (operation == Operation::Read && !input.is_empty())
    {
        return Err(Failure::before_spawn("bounded opcode input"));
    }
    // Before spawn, failed context checks cannot abandon a live helper.
    context.check_roots();
    assert_eq!(context.root.identity, context.record.case_identity);
    assert_eq!(
        context.root.path.to_str().unwrap(),
        context.record.case_root
    );
    context
        .deadline
        .try_remaining()
        .map_err(Failure::before_spawn)?;
    let (input_parent, input_child) = pair(false)?;
    let (output_parent, output_child) = pair(true)?;
    let (error_parent, error_child) = pair(true)?;
    let mut command = Command::new("/record-helper");
    command
        .env_clear()
        .args([
            operation.text().to_owned(),
            name.stem().to_owned(),
            context.record.case_root.clone(),
            context.root.identity.device.to_string(),
            context.root.identity.inode.to_string(),
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
    // Command can retain configured Stdio; close ALL parent-held child ends now.
    drop(command);
    let child = result.map_err(|_| Failure::before_spawn("helper spawn"))?;
    let sockets = Sockets {
        input: input_parent,
        output: output_parent,
        errors: error_parent,
    };
    let (frame, status) = record_pump::run(child, sockets, input, context.deadline)?;
    let result = record_protocol::decode(&frame, operation, name, input.len())
        .map_err(|code| Failure::collected(code, status))?;
    // H was actually collected; fallible checks cannot leak its ownership now.
    record_validation::after_collection(context, status)?;
    Ok((result, status))
}
