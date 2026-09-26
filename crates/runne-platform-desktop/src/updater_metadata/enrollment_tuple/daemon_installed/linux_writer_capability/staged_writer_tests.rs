use std::{
    os::unix::fs::{PermissionsExt as _, symlink},
    path::Path,
};

use sha2::{Digest as _, Sha256};

use super::verified_staged_writer_artifact;

fn private_directory(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn write_staged(root: &Path, bytes: &[u8]) -> (std::path::PathBuf, [u8; 32]) {
    let runtime = root.join("bundled-runtime");
    private_directory(&runtime);
    let activation = runtime.join(".desktop-protected-activation");
    private_directory(&activation);
    let stage = activation.join("executables-v1");
    private_directory(&stage);
    let digest: [u8; 32] = Sha256::digest(bytes).into();
    let target = stage.join(format!("{}-{}.runned", hex::encode(digest), bytes.len()));
    std::fs::write(&target, bytes).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o500)).unwrap();
    symlink(target.file_name().unwrap(), stage.join("runne")).unwrap();
    (runtime, digest)
}

#[test]
fn launches_signed_writer_from_exact_private_path_bound_by_daemon_policy() {
    let root = tempfile::tempdir().unwrap();
    let packaged_writer = root.path().join("AppDir/usr/bin/runne");
    std::fs::create_dir_all(packaged_writer.parent().unwrap()).unwrap();
    let bytes = b"signed installed writer";
    std::fs::write(&packaged_writer, bytes).unwrap();
    let (runtime, digest) = write_staged(root.path(), bytes);

    let artifact = verified_staged_writer_artifact(&runtime, digest, bytes.len() as u64, [7; 32])
        .expect("installed writer's signed bytes have a trusted staged path");
    let policy_writer = std::fs::canonicalize(
        std::fs::canonicalize(&runtime)
            .unwrap()
            .join(".desktop-protected-activation/executables-v1/runne"),
    )
    .unwrap();
    assert_eq!(artifact.executable(), policy_writer);
    assert_ne!(artifact.executable(), std::fs::canonicalize(packaged_writer).unwrap());
    assert_eq!(artifact.image_digest(), digest);
}

#[test]
fn rejects_wrong_digest_missing_alias_and_alias_to_outside_file() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"signed installed writer";
    let (runtime, digest) = write_staged(root.path(), bytes);
    let stage = runtime.join(".desktop-protected-activation/executables-v1");
    assert!(verified_staged_writer_artifact(&runtime, [8; 32], bytes.len() as u64, [7; 32]).is_err());

    std::fs::remove_file(stage.join("runne")).unwrap();
    assert!(verified_staged_writer_artifact(&runtime, digest, bytes.len() as u64, [7; 32]).is_err());

    let outside = root.path().join("outside.runned");
    std::fs::write(&outside, bytes).unwrap();
    std::fs::set_permissions(&outside, std::fs::Permissions::from_mode(0o500)).unwrap();
    symlink(&outside, stage.join("runne")).unwrap();
    assert!(verified_staged_writer_artifact(&runtime, digest, bytes.len() as u64, [7; 32]).is_err());
}

#[test]
fn rejects_staged_writer_with_mutated_mode_or_contents() {
    let root = tempfile::tempdir().unwrap();
    let bytes = b"signed installed writer";
    let (runtime, digest) = write_staged(root.path(), bytes);
    let stage = runtime.join(".desktop-protected-activation/executables-v1");
    let target = std::fs::canonicalize(stage.join("runne")).unwrap();

    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(verified_staged_writer_artifact(&runtime, digest, bytes.len() as u64, [7; 32]).is_err());
    let mut changed = bytes.to_vec();
    changed[0] ^= 1;
    std::fs::write(&target, changed).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(verified_staged_writer_artifact(&runtime, digest, bytes.len() as u64, [7; 32]).is_err());
}
