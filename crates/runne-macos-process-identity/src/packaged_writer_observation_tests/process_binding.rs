#![allow(unsafe_code)]
#![cfg(test)]

use std::ffi::CString;
use std::fs::File;
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::PermissionsExt as _;

use crate::ffi::observe_executable_vnode_matching_file;
use crate::packaged_writer_observation::package::PackagedWriterArtifacts;
use crate::packaged_writer_observation::security_code::NativeCodeObservation;

use super::support::PackageFixture;

#[test]
fn current_main_executable_mapping_matches_its_open_descriptor() {
    let executable = File::open(std::env::current_exe().unwrap()).unwrap();
    let pid = NonZeroU32::new(std::process::id()).unwrap();

    assert!(observe_executable_vnode_matching_file(pid, &executable).is_ok());
}

#[test]
fn executable_mmap_alone_cannot_replace_the_security_code_main_executable() {
    let fixture = PackageFixture::new();
    let writer = fixture.role("runne");
    let source = fixture.role("mmap-only.c");
    std::fs::write(&source, "int runne_mmap_only(void) { return 7; }").unwrap();
    assert!(
        std::process::Command::new("/usr/bin/clang")
            .args(["-dynamiclib", "-o"])
            .arg(&writer)
            .arg(&source)
            .status()
            .unwrap()
            .success()
    );
    std::fs::set_permissions(&writer, std::fs::Permissions::from_mode(0o755)).unwrap();
    let mapped = File::open(&writer).unwrap();
    let mapping = ExecutableImageMapping::new(&writer);
    let package = PackagedWriterArtifacts::capture_for_test(fixture.application()).unwrap();
    let code = NativeCodeObservation::capture_self().unwrap();
    let pid = NonZeroU32::new(std::process::id()).unwrap();

    assert!(observe_executable_vnode_matching_file(pid, &mapped).is_ok());
    assert!(
        package
            .test_only_require_writer_main_locator(code.main_executable())
            .is_err()
    );
    drop(mapping);
}

struct ExecutableImageMapping {
    handle: *mut libc::c_void,
}

impl ExecutableImageMapping {
    fn new(path: &std::path::Path) -> Self {
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let handle = unsafe { libc::dlopen(path.as_ptr(), libc::RTLD_NOW) };
        assert!(!handle.is_null(), "dlopen executable image failed");
        Self { handle }
    }
}

impl Drop for ExecutableImageMapping {
    fn drop(&mut self) {
        assert_eq!(unsafe { libc::dlclose(self.handle) }, 0);
    }
}
