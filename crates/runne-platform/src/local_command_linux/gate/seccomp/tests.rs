use super::{PROGRAM_CAPACITY, audit_arch, build};
use crate::local_command_linux::policy::NativeFsProfile;

#[test]
fn worst_case_composite_network_none_program_fits_capacity() {
    let arch = audit_arch().expect("test host has an audited architecture");
    let program = build(arch, true, true, None);
    assert!(
        program.instruction_count() <= PROGRAM_CAPACITY,
        "seccomp program overflow: {} instructions exceed capacity {PROGRAM_CAPACITY}",
        program.instruction_count()
    );
}

#[test]
fn partial_rights_guard_program_fits_capacity() {
    let arch = audit_arch().expect("test host has an audited architecture");
    let program = build(
        arch,
        true,
        false,
        Some(NativeFsProfile {
            allowed_access: 0,
            write_allowed: false,
            metadata_allowed: false,
            rename_allowed: false,
        }),
    );
    assert!(program.instruction_count() <= PROGRAM_CAPACITY);
    for syscall in [
        libc::SYS_fallocate,
        libc::SYS_fchmodat2,
        libc::SYS_renameat2,
    ] {
        assert!(
            program.0[..program.1].iter().any(
                |instruction| instruction.code == super::JEQ && instruction.k == syscall as u32
            )
        );
    }
}
