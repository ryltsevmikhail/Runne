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
fn retained_package_exposes_exact_role_digests_inside_the_crate() {
    let fixture = PackageFixture::new();
    let package = PackagedWriterArtifacts::capture_for_test(fixture.application()).unwrap();

    assert_eq!(
        hex(package.desktop_digest()),
        "1119593faf9665a14105817a3facaeeb17962178be74f1b47bd5bffebe5d3c20"
    );
    assert_eq!(
        hex(package.writer_digest()),
        "3a1dc6ead6434388e4961fe76bd112a31f7b66a3c074c84766a859b46ad3f21d"
    );
    assert_eq!(
        hex(package.daemon_digest()),
        "d4375538e8bc2b9b78c2c780d9028d761f7ec9527dd0040153a107d348033f5e"
    );
    assert_eq!(
        hex(package.contract_digest()),
        "4f60ba79cba832dbc098dc5c13aac548152b6ccb60d75ab80f7dff2d91a4cdc3"
    );
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

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
