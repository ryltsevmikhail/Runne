#![cfg(test)]

use crate::packaged_writer_observation::artifact::test_only_valid_file_shape;
use crate::packaged_writer_observation::package::{
    PackagedWriterArtifacts, test_only_is_fixed_writer_locator, test_only_valid_directory_shape,
};

use super::support::PackageFixture;

#[test]
fn fixed_descriptor_opened_package_captures_and_revalidates() {
    let fixture = PackageFixture::new();
    let package = PackagedWriterArtifacts::capture_for_test(fixture.application()).unwrap();

    assert!(package.revalidate().is_ok());
    assert!(PackagedWriterArtifacts::capture_from_writer_main(&fixture.role("runne")).is_ok());
    assert!(PackagedWriterArtifacts::capture_from_writer_main(&fixture.role("runned")).is_err());
    assert!(test_only_is_fixed_writer_locator(&fixture.role("runne")));
    assert!(!test_only_is_fixed_writer_locator(
        &fixture
            .application()
            .with_file_name("NotRunne.app")
            .join("Contents/MacOS/runne")
    ));
}

#[test]
fn owner_or_device_skew_is_rejected_by_the_real_shape_predicates() {
    let regular = u32::from(libc::S_IFREG | 0o755);
    assert!(test_only_valid_file_shape(
        (7, 501),
        (7, 501, regular, 1, 8),
        true
    ));
    assert!(!test_only_valid_file_shape(
        (7, 501),
        (8, 501, regular, 1, 8),
        true
    ));
    assert!(!test_only_valid_file_shape(
        (7, 501),
        (7, 502, regular, 1, 8),
        true
    ));

    let directory = u32::from(libc::S_IFDIR | 0o755);
    assert!(test_only_valid_directory_shape(
        (7, 501),
        (7, 501, directory, 2)
    ));
    assert!(!test_only_valid_directory_shape(
        (7, 501),
        (8, 501, directory, 2)
    ));
    assert!(!test_only_valid_directory_shape(
        (7, 501),
        (7, 502, directory, 2)
    ));
}
