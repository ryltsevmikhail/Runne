//! Draft real direct-child guard regressions; guest-only, not lost-ACK history.
use super::{channel, context::CaseContext, owned_role::OwnedRole, transport_fd,
    zero_response::ZeroResponse};
use std::{io, net::Shutdown, os::unix::{net::UnixStream, process::ExitStatusExt},
    process::{Command, Stdio}};

pub(super) const SELECTOR: &str =
    "store::permission_modes::tests_capture_retention::lost_ack::guard_history";
const ROLE: &str = "RUNNE_R05_LOST_ACK_GUARD_ROLE_V1";
const CASE: &str = "RUNNE_R05_CASE_CONTEXT_V1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Mode { SilentAbort, ByteAbort, LateByteAbort, EofAbort, NormalExit }
impl Mode {
    fn text(self) -> &'static str {
        match self { Self::SilentAbort => "silent-abort", Self::ByteAbort => "byte-abort",
            Self::LateByteAbort => "late-byte-abort", Self::EofAbort => "eof-abort",
            Self::NormalExit => "normal-exit" }
    }
}
fn parse(role: Option<&str>, case: bool, args: &[&str]) -> Result<Option<Mode>, &'static str> {
    if args != ["/test-store", "--exact", SELECTOR, "--show-output", "--test-threads=1"] {
        return Err("dedicated exact serial selector required");
    }
    match (role, case) {
        (None, false) => Ok(None),
        (Some("silent-abort"), true) => Ok(Some(Mode::SilentAbort)),
        (Some("byte-abort"), true) => Ok(Some(Mode::ByteAbort)),
        (Some("late-byte-abort"), true) => Ok(Some(Mode::LateByteAbort)),
        (Some("eof-abort"), true) => Ok(Some(Mode::EofAbort)),
        (Some("normal-exit"), true) => Ok(Some(Mode::NormalExit)),
        _ => Err("closed role/context pair required"),
    }
}
pub(super) fn current() -> Option<Mode> {
    let args: Vec<_> = std::env::args_os().take(6).collect();
    let text: Vec<_> = args.iter().map(|arg| arg.to_str().unwrap()).collect();
    let role = std::env::var_os(ROLE);
    parse(role.as_ref().map(|arg| arg.to_str().unwrap()),
        std::env::var_os(CASE).is_some(), &text).unwrap()
}

// Called only after current() returned the admitted role and context inherited.
pub(super) fn child(context: &CaseContext, mode: Mode) -> ! {
    context.check_child();
    assert_eq!(current(), Some(mode));
    let (mut data, mut control) = transport_fd::take_inherited().unwrap();
    if mode == Mode::ByteAbort {
        channel::send(&mut data, b"forbidden", context.deadline).unwrap();
    }
    if mode == Mode::EofAbort { data.shutdown(Shutdown::Write).unwrap(); }
    // This readiness means only guard-role admission/optional-byte publication.
    // It is explicitly NOT native readiness, a commit cut or receipt evidence.
    channel::send(&mut control, b"guard-ready", context.deadline).unwrap();
    control.shutdown(Shutdown::Write).unwrap();
    assert_eq!(channel::receive(&mut control, context.deadline).unwrap(), b"finish");
    context.check_child();
    if mode == Mode::LateByteAbort {
        channel::send(&mut data, b"late-forbidden", context.deadline).unwrap();
    }
    std::hint::black_box(&data); // result endpoint remains open until role death
    if mode == Mode::NormalExit { std::process::exit(0); }
    std::process::abort()
}

fn spawn(context: &CaseContext, mode: Mode) -> (OwnedRole, UnixStream, UnixStream) {
    assert_eq!(current(), None);
    context.check_roots();
    let (supervisor_data, child_data) = UnixStream::pair().unwrap();
    let (supervisor_control, child_control) = UnixStream::pair().unwrap();
    let mut command = Command::new("/test-store");
    command.args(["--exact", SELECTOR, "--show-output", "--test-threads=1"]);
    context.command(&mut command);
    command.env(ROLE, mode.text()).stdin(Stdio::null())
        .stdout(Stdio::null()).stderr(Stdio::null());
    // Transport consumes Command and closes its captures before returning Child.
    let child = transport_fd::spawn(command, child_data, child_control).unwrap();
    (OwnedRole::from_child(child, context.deadline), supervisor_data, supervisor_control)
}

pub(super) fn regressions(context: &CaseContext) {
    for mode in [Mode::SilentAbort, Mode::ByteAbort, Mode::LateByteAbort, Mode::EofAbort, Mode::NormalExit] {
        let (mut owner, data, mut control) = spawn(context, mode);
        assert_eq!(channel::receive(&mut control, context.deadline).unwrap(), b"guard-ready");
        let mut zero = ZeroResponse::new(data, &owner);
        if matches!(mode, Mode::ByteAbort | Mode::EofAbort) {
            assert_eq!(zero.before_abort(&mut owner).unwrap_err().kind(), io::ErrorKind::InvalidData);
            // A consumed forbidden byte may never become a later successful probe.
            assert_eq!(zero.before_abort(&mut owner).unwrap_err().kind(), io::ErrorKind::InvalidData);
        } else { zero.before_abort(&mut owner).unwrap(); }
        channel::send(&mut control, b"finish", context.deadline).unwrap();
        control.shutdown(Shutdown::Write).unwrap();
        let status = owner.collect().unwrap();
        if mode == Mode::NormalExit {
            assert_eq!(status.code(), Some(0));
            assert_eq!(status.signal(), None);
        } else {
            assert_eq!(status.code(), None);
            assert_eq!(status.signal(), Some(6));
        }
        let result = zero.after_collected_abort(&owner);
        if mode == Mode::SilentAbort { result.unwrap(); }
        else { assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData); }
        drop(control);
        drop(owner);
        context.check_roots();
    }
    // Caller must independently collect adopted descendants/ECHILD and perform
    // checked case/RAM/root cleanup; these primitive assertions do not prove it.
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn role_requires_closed_mode_context_and_exact_selector() {
        let args = ["/test-store", "--exact", SELECTOR, "--show-output", "--test-threads=1"];
        assert_eq!(parse(None, false, &args), Ok(None));
        for mode in [Mode::SilentAbort, Mode::ByteAbort, Mode::LateByteAbort, Mode::EofAbort, Mode::NormalExit] {
            assert_eq!(parse(Some(mode.text()), true, &args), Ok(Some(mode)));
            assert!(parse(Some(mode.text()), false, &args).is_err());
        }
        assert!(parse(None, true, &args).is_err());
        assert!(parse(Some("writer"), true, &args).is_err());
        for index in 0..args.len() {
            let mut bad = args;
            bad[index] = "other";
            assert!(parse(None, false, &bad).is_err());
        }
        assert!(parse(None, false, &args[..4]).is_err());
        let mut surplus = args.to_vec();
        surplus.push("unexpected");
        assert!(parse(None, false, &surplus).is_err());
    }
}

// Distinct actual Child guards, not manufactured numeric identity/status.
pub(super) fn association_and_missing_observation_controls(context: &CaseContext) {
    let (mut original, data, mut original_control) = spawn(context, Mode::SilentAbort);
    let (mut other, mut other_data, mut other_control) = spawn(context, Mode::SilentAbort);
    for control in [&mut original_control, &mut other_control] {
        assert_eq!(channel::receive(control, context.deadline).unwrap(), b"guard-ready");
    }
    let mut zero = ZeroResponse::new(data, &original);
    assert_eq!(zero.before_abort(&mut other).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(zero.before_abort(&mut original).unwrap_err().kind(), io::ErrorKind::InvalidData);
    for control in [&mut original_control, &mut other_control] {
        channel::send(control, b"finish", context.deadline).unwrap();
        control.shutdown(Shutdown::Write).unwrap();
    }
    assert_eq!(original.collect().unwrap().signal(), Some(6));
    assert_eq!(other.collect().unwrap().signal(), Some(6));
    assert_eq!(zero.after_collected_abort(&original).unwrap_err().kind(), io::ErrorKind::InvalidData);
    channel::require_eof_without_bytes(&mut other_data, context.deadline).unwrap();
    drop(other_data);
    drop((original_control, other_control, original, other));

    let (mut owner, data, mut control) = spawn(context, Mode::SilentAbort);
    assert_eq!(channel::receive(&mut control, context.deadline).unwrap(), b"guard-ready");
    let zero = ZeroResponse::new(data, &owner); // no before_abort observation
    channel::send(&mut control, b"finish", context.deadline).unwrap();
    control.shutdown(Shutdown::Write).unwrap();
    assert_eq!(owner.collect().unwrap().signal(), Some(6));
    assert_eq!(zero.after_collected_abort(&owner).unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop((control, owner));

    let (mut owner, data, mut control) = spawn(context, Mode::NormalExit);
    assert_eq!(channel::receive(&mut control, context.deadline).unwrap(), b"guard-ready");
    let mut zero = ZeroResponse::new(data, &owner);
    channel::send(&mut control, b"finish", context.deadline).unwrap();
    control.shutdown(Shutdown::Write).unwrap();
    assert_eq!(owner.collect().unwrap().code(), Some(0));
    assert_eq!(zero.before_abort(&mut owner).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(zero.before_abort(&mut owner).unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(zero.after_collected_abort(&owner).unwrap_err().kind(), io::ErrorKind::InvalidData);
    drop((control, owner));
    context.check_roots();
}
