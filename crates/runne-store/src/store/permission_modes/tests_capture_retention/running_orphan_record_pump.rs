//! One-thread bounded socket pump; failures retain an uncollected real Child.
use super::clock::Deadline;
use super::record_protocol::{ERROR_CAP, OUTPUT_CAP};
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::process::{Child, ExitStatus};
use std::time::Duration;

#[derive(Debug)]
pub(super) struct Failure {
    pub primary: &'static str,
    pub secondary: Vec<&'static str>,
    pub stderr: Vec<u8>,
    pub status: Option<ExitStatus>,
    // Caller MUST retain this through fatal teardown; None alone is not proof
    // unless status records actual collection or the helper was never spawned.
    pub uncollected: Option<Child>,
}
impl Failure {
    pub(super) fn before_spawn(primary: &'static str) -> Self {
        Self {
            primary,
            secondary: vec![],
            stderr: vec![],
            status: None,
            uncollected: None,
        }
    }
    pub(super) fn collected(primary: &'static str, status: ExitStatus) -> Self {
        Self {
            primary,
            secondary: vec![],
            stderr: vec![],
            status: Some(status),
            uncollected: None,
        }
    }
}

pub(super) struct Sockets {
    pub input: UnixStream,
    pub output: UnixStream,
    pub errors: UnixStream,
}

fn drain(
    socket: &mut UnixStream,
    bytes: &mut Vec<u8>,
    cap: usize,
    eof: &mut bool,
    deadline: Deadline,
) -> Result<(), &'static str> {
    if *eof {
        return Ok(());
    }
    let mut chunk = [0u8; 1024];
    loop {
        deadline.try_remaining()?;
        let size = (cap + 1 - bytes.len()).min(chunk.len());
        match socket.read(&mut chunk[..size]) {
            Ok(0) => {
                *eof = true;
                return Ok(());
            }
            Ok(n) => {
                bytes.extend_from_slice(&chunk[..n]);
                if bytes.len() > cap {
                    return Err("helper stream cap exceeded");
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return Ok(()),
            Err(_) => return Err("helper socket read"),
        }
    }
}

fn drain_after_collected_failure(
    sockets: &mut Sockets,
    output: &mut Vec<u8>,
    errors: &mut Vec<u8>,
    output_eof: &mut bool,
    errors_eof: &mut bool,
    deadline: Deadline,
) -> Result<(), &'static str> {
    loop {
        if *output_eof && *errors_eof {
            return Ok(());
        }
        deadline.try_remaining()?;
        drain(
            &mut sockets.output,
            output,
            OUTPUT_CAP,
            output_eof,
            deadline,
        )?;
        drain(&mut sockets.errors, errors, ERROR_CAP, errors_eof, deadline)?;
        if *output_eof && *errors_eof {
            return Ok(());
        }
        let left = deadline.try_remaining()?;
        std::thread::sleep(left.min(Duration::from_millis(1)));
    }
}

fn exchange(
    child: &mut Child,
    sockets: &mut Sockets,
    input: &[u8],
    deadline: Deadline,
    output: &mut Vec<u8>,
    errors: &mut Vec<u8>,
    status: &mut Option<ExitStatus>,
    secondary: &mut Vec<&'static str>,
) -> Result<(), &'static str> {
    let mut sent = 0;
    let (mut shut, mut output_eof, mut errors_eof) = (false, false, false);
    loop {
        deadline.try_remaining()?;
        if sent < input.len() {
            match sockets.input.write(&input[sent..]) {
                Ok(0) => return Err("zero progress helper input"),
                Ok(n) => sent += n,
                Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => {}
                Err(_) => return Err("helper socket write"),
            }
        }
        if sent == input.len() && !shut {
            sockets
                .input
                .shutdown(Shutdown::Write)
                .map_err(|_| "helper input EOF shutdown")?;
            shut = true;
        }
        drain(
            &mut sockets.output,
            output,
            OUTPUT_CAP,
            &mut output_eof,
            deadline,
        )?;
        drain(
            &mut sockets.errors,
            errors,
            ERROR_CAP,
            &mut errors_eof,
            deadline,
        )?;
        if status.is_none() {
            *status = child.try_wait().map_err(|_| "helper try_wait")?;
        }
        if let Some(observed) = status.as_ref() {
            if !observed.success() {
                // Retain nonzero as primary, but drain its late bounded diagnostic
                // before channels are torn down, without any renewed deadline.
                if let Err(code) = drain_after_collected_failure(
                    sockets,
                    output,
                    errors,
                    &mut output_eof,
                    &mut errors_eof,
                    deadline,
                ) {
                    if secondary.len() < 8 {
                        secondary.push(code);
                    }
                }
                return Err("helper nonzero or signal");
            }
            if output_eof && errors_eof {
                if !errors.is_empty() {
                    return Err("unexpected success stderr");
                }
                if sent != input.len() || !shut {
                    return Err("helper exited before input completion");
                }
                deadline.try_remaining()?;
                return Ok(());
            }
        }
        let left = deadline.try_remaining()?;
        std::thread::sleep(left.min(Duration::from_millis(1)));
    }
}

pub(super) fn run(
    mut child: Child,
    mut sockets: Sockets,
    input: &[u8],
    deadline: Deadline,
) -> Result<(Vec<u8>, ExitStatus), Failure> {
    let (mut output, mut errors, mut status) = (Vec::new(), Vec::new(), None);
    let mut secondary = Vec::new();
    let result = exchange(
        &mut child,
        &mut sockets,
        input,
        deadline,
        &mut output,
        &mut errors,
        &mut status,
        &mut secondary,
    );
    if result.is_ok() {
        if let Some(observed) = status {
            if observed.success() {
                return Ok((output, observed));
            }
        }
    }
    let primary = result
        .err()
        .unwrap_or("missing actual collected exit0 witness");
    for socket in [&sockets.input, &sockets.output, &sockets.errors] {
        if socket.shutdown(Shutdown::Both).is_err() && secondary.len() < 8 {
            secondary.push("failure socket shutdown");
        }
    }
    if status.is_none() {
        match child.try_wait() {
            Ok(value) => status = value,
            Err(_) => {
                if secondary.len() < 8 {
                    secondary.push("failure initial try_wait");
                }
            }
        }
    }
    if status.is_none() && deadline.try_remaining().is_ok() {
        if child.kill().is_err() && secondary.len() < 8 {
            secondary.push("owned helper kill");
        }
        while let Ok(left) = deadline.try_remaining() {
            match child.try_wait() {
                Ok(Some(value)) => {
                    status = Some(value);
                    break;
                }
                Ok(None) => std::thread::sleep(left.min(Duration::from_millis(1))),
                Err(_) => {
                    if secondary.len() < 8 {
                        secondary.push("failure collection");
                    }
                    break;
                }
            }
        }
    }
    errors.truncate(ERROR_CAP);
    let uncollected = if status.is_none() { Some(child) } else { None };
    Err(Failure {
        primary,
        secondary,
        stderr: errors,
        status,
        uncollected,
    })
}

#[cfg(test)]
#[path = "running_orphan_record_pump_tests.rs"]
mod tests;
