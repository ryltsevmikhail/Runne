#![cfg(test)]

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

use crate::packaged_writer_observation::package::PackagedWriterArtifacts;

use super::support::PackageFixture;

#[test]
fn symlinked_role_or_intermediate_directory_is_rejected() {
    for intermediate in [false, true] {
        let fixture = PackageFixture::new();
        if intermediate {
            let resources = fixture.application().join("Contents/Resources");
            let moved = fixture.application().join("Contents/Resources.real");
            fs::rename(&resources, &moved).unwrap();
            symlink(&moved, resources).unwrap();
        } else {
            let writer = fixture.role("runne");
            fs::rename(&writer, fixture.role("writer.real")).unwrap();
            symlink(fixture.role("writer.real"), writer).unwrap();
        }
        assert!(PackagedWriterArtifacts::capture_for_test(fixture.application()).is_err());
    }
}

#[test]
fn hardlink_special_empty_oversize_or_writable_role_is_rejected() {
    for mutation in 0..5 {
        let fixture = PackageFixture::new();
        let daemon = fixture.role("runned");
        match mutation {
            0 => {
                fs::remove_file(&daemon).unwrap();
                fs::hard_link(fixture.role("runne"), daemon).unwrap();
            }
            1 => {
                fs::remove_file(&daemon).unwrap();
                mkfifo(&daemon, Mode::S_IRUSR | Mode::S_IWUSR).unwrap();
                assert!(PackagedWriterArtifacts::capture_for_test(fixture.application()).is_err());
                continue;
            }
            2 => fs::write(&daemon, []).unwrap(),
            3 => fs::File::create(&daemon)
                .unwrap()
                .set_len(64 * 1024 * 1024 + 1)
                .unwrap(),
            4 => fs::set_permissions(&daemon, fs::Permissions::from_mode(0o775)).unwrap(),
            _ => unreachable!(),
        }
        assert!(PackagedWriterArtifacts::capture_for_test(fixture.application()).is_err());
    }
}

#[test]
fn writable_root_or_duplicate_role_bytes_are_rejected() {
    for duplicate in [false, true] {
        let fixture = PackageFixture::new();
        if duplicate {
            let bytes = fs::read(fixture.role("runne")).unwrap();
            fs::write(fixture.role("runned"), bytes).unwrap();
        } else {
            fs::set_permissions(fixture.application(), fs::Permissions::from_mode(0o775)).unwrap();
        }
        assert!(PackagedWriterArtifacts::capture_for_test(fixture.application()).is_err());
    }
}

#[test]
fn writable_intermediate_directory_is_rejected() {
    let fixture = PackageFixture::new();
    fs::set_permissions(
        fixture.application().join("Contents/Resources"),
        fs::Permissions::from_mode(0o775),
    )
    .unwrap();

    assert!(PackagedWriterArtifacts::capture_for_test(fixture.application()).is_err());
}

#[test]
fn root_or_role_replacement_and_same_size_mutation_fail_final_revalidation() {
    for mutation in 0..3 {
        let fixture = PackageFixture::new();
        let package = PackagedWriterArtifacts::capture_for_test(fixture.application()).unwrap();
        match mutation {
            0 => fixture.replace_application(),
            1 => {
                let writer = fixture.role("runne");
                fs::rename(&writer, fixture.role("runne.old")).unwrap();
                fs::write(&writer, b"writer-v2").unwrap();
                fs::set_permissions(writer, fs::Permissions::from_mode(0o755)).unwrap();
            }
            2 => fs::write(fixture.role("runne"), b"mutate-v1").unwrap(),
            _ => unreachable!(),
        }
        assert!(package.revalidate().is_err());
    }
}
