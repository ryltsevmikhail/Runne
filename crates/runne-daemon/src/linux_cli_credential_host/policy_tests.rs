use super::*;
use std::os::unix::fs::PermissionsExt;
#[test]
fn symlinks_writable_images_and_wrong_pins_are_rejected() {
    let directory =
        tempfile::tempdir_in(std::env::current_exe().unwrap().parent().unwrap()).unwrap();
    let image = directory.path().join("image");
    std::fs::write(&image, b"synthetic-image").unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(image_digest(&image).is_ok());
    let alias = directory.path().join("alias");
    std::os::unix::fs::symlink(&image, &alias).unwrap();
    assert!(image_digest(&alias).is_err());
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o720)).unwrap();
    assert!(image_digest(&image).is_err());
    let pins = LinuxCliCredentialHostConfig {
        cli_sha256: "1".repeat(64),
        daemon_sha256: "2".repeat(64),
        host_sha256: "3".repeat(64),
    };
    assert!(validate_pins(&pins, [3; 32], [4; 32], [5; 32]).is_err());
}
