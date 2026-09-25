use super::{capture_paths, open_rooted_path};
use std::os::unix::fs::PermissionsExt as _;

fn fixture() -> (tempfile::TempDir, [std::path::PathBuf; 4]) {
    let root = tempfile::tempdir().unwrap();
    let bin = root.path().join("bin");
    let contract = root.path().join("resources/contracts/gocode-ui-client-3");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::create_dir_all(&contract).unwrap();
    let paths = [
        bin.join("runne-desktop"),
        bin.join("runne"),
        bin.join("runned"),
        contract.join("bundle.json"),
    ];
    for (index, path) in paths.iter().enumerate() {
        std::fs::write(path, format!("fixture-{index}")).unwrap();
    }
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).unwrap();
    (root, paths)
}

#[test]
fn rooted_linux_paths_are_rechecked_against_the_opened_file_identity() {
    let (_root, paths) = fixture();
    let retained = capture_paths(&paths, false).unwrap();
    retained.measure().unwrap();

    let replacement = paths[1].with_extension("replacement");
    std::fs::write(&replacement, b"different writer bytes").unwrap();
    std::fs::rename(&replacement, &paths[1]).unwrap();

    assert!(retained.confirm_current().is_err());
}

#[test]
fn rooted_linux_open_rejects_symlink_components() {
    let (_root, paths) = fixture();
    let retained = capture_paths(&paths, false).unwrap();
    let root = std::fs::File::open(retained.application.as_path()).unwrap();
    let relative = paths[0]
        .strip_prefix(retained.application.as_path())
        .unwrap();
    let directory = relative.parent().unwrap();
    let link = retained.application.join("linked");
    std::os::unix::fs::symlink(directory, &link).unwrap();
    let redirected = std::path::Path::new("linked").join(relative.file_name().unwrap());
    assert!(open_rooted_path(&root, &redirected).is_err());
}

#[test]
fn linux_refresh_matches_only_the_same_rooted_native_files() {
    let (_root, paths) = fixture();
    let retained = capture_paths(&paths, false).unwrap();
    let fresh = capture_paths(&paths, false).unwrap();
    assert!(retained.matches_retained(&fresh).unwrap());

    let replacement = paths[1].with_extension("replacement");
    std::fs::write(&replacement, b"replacement writer").unwrap();
    std::fs::rename(replacement, &paths[1]).unwrap();
    let fresh = capture_paths(&paths, false).unwrap();
    assert!(retained.matches_retained(&fresh).is_err());
}

#[test]
fn authenticated_peer_resolution_rejects_the_daemon_process_as_its_own_desktop() {
    let (_root, paths) = fixture();
    let resource = paths[3]
        .ancestors()
        .nth(2)
        .expect("fixture resource directory");
    let (stream, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(super::resolve_from_authenticated_peer(&stream, resource).is_err());
}
