//! Dedicated libtest selector admission; process ownership remains separate.
use super::context::CaseContext;
use std::process::Command;

pub(super) const SELECTOR: &str = "store::permission_modes::tests_capture_retention::running_orphan::running_child_writer_abort_recovers_unknown";
const ROLE: &str = "RUNNE_R05_ROLE_V1";
const CASE: &str = "RUNNE_R05_CASE_CONTEXT_V1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    Writer,
    Recovery,
}

fn parse(role: Option<&str>, case: bool, args: &[&str]) -> Result<Option<Role>, &'static str> {
    if args
        != [
            "/test-store",
            "--exact",
            SELECTOR,
            "--show-output",
            "--test-threads=1",
        ]
    {
        return Err("dedicated exact selector and serial libtest invocation required");
    }
    match (role, case) {
        (None, false) => Ok(None),
        (Some("writer"), true) => Ok(Some(Role::Writer)),
        (Some("recovery"), true) => Ok(Some(Role::Recovery)),
        _ => Err("closed role and context must occur together"),
    }
}

pub(super) fn current() -> Option<Role> {
    // At most six arguments are allocated; any extra argument is refused.
    let args: Vec<_> = std::env::args_os().take(6).collect();
    assert_eq!(args.len(), 5);
    let text: Vec<_> = args.iter().map(|s| s.to_str().unwrap()).collect();
    let role = std::env::var_os(ROLE);
    let role = role.as_ref().map(|s| s.to_str().unwrap());
    parse(role, std::env::var_os(CASE).is_some(), &text).unwrap()
}

pub(super) fn child(context: &CaseContext, role: Role) -> Command {
    assert_eq!(current(), None, "only the original S dispatches W/R");
    let mut command = Command::new("/test-store");
    command.args(["--exact", SELECTOR, "--show-output", "--test-threads=1"]);
    context.command(&mut command);
    command.env(
        ROLE,
        match role {
            Role::Writer => "writer",
            Role::Recovery => "recovery",
        },
    );
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selector_and_role_are_closed_not_an_arbitrary_environment_dispatch() {
        let args = [
            "/test-store",
            "--exact",
            SELECTOR,
            "--show-output",
            "--test-threads=1",
        ];
        assert_eq!(parse(None, false, &args), Ok(None));
        assert_eq!(parse(Some("writer"), true, &args), Ok(Some(Role::Writer)));
        assert_eq!(
            parse(Some("recovery"), true, &args),
            Ok(Some(Role::Recovery))
        );
        for (role, case) in [
            (None, true),
            (Some("writer"), false),
            (Some("recovery"), false),
            (Some(""), true),
            (Some("control"), true),
            (Some("supervisor"), true),
            (Some("writer\0"), true),
        ] {
            assert!(parse(role, case, &args).is_err());
        }
        for index in 0..args.len() {
            let mut bad = args;
            bad[index] = "other";
            assert!(parse(Some("writer"), true, &bad).is_err());
        }
        assert!(parse(None, false, &args[..4]).is_err());
    }
}
