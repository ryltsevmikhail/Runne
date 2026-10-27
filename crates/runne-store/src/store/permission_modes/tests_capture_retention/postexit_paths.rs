use serde::{Serialize, de::DeserializeOwned};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path};

pub(super) fn component(name: &str) {
    let mut parts = Path::new(name).components();
    assert!(matches!(parts.next(), Some(Component::Normal(_))));
    assert!(parts.next().is_none());
    assert!(!name.is_empty() && name.len() <= 255);
}
fn uid() -> u32 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let values: Vec<u32> = status
        .lines()
        .find_map(|s| s.strip_prefix("Uid:"))
        .unwrap()
        .split_whitespace()
        .map(|s| s.parse().unwrap())
        .collect();
    assert_eq!(values.len(), 4);
    values[1]
}
fn ancestry(path: &Path) {
    assert!(path.is_absolute());
    for ancestor in path.ancestors() {
        let info = std::fs::symlink_metadata(ancestor).unwrap();
        assert!(!info.file_type().is_symlink());
        assert_eq!(std::fs::canonicalize(ancestor).unwrap(), ancestor);
    }
}
pub(super) fn directory(path: &Path) {
    ancestry(path);
    let info = std::fs::symlink_metadata(path).unwrap();
    assert!(info.is_dir());
    assert_eq!(info.uid(), uid());
}
pub(super) fn private_root(path: &Path) {
    directory(path);
    assert_eq!(
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o700
    );
}
pub(super) fn regular(path: &Path) {
    ancestry(path);
    let info = std::fs::symlink_metadata(path).unwrap();
    assert!(info.is_file());
    assert_eq!(info.uid(), uid());
}
fn metadata_name(name: &str) {
    assert!(matches!(
        name,
        "area.json" | "cut.json" | "result.json" | "request.json"
    ));
}
pub(super) fn write<T: Serialize>(root: &Path, name: &str, value: &T) {
    private_root(root);
    metadata_name(name);
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 16 * 1024);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(root.join(name))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.flush().unwrap();
    file.sync_all().unwrap();
    File::open(root).unwrap().sync_all().unwrap();
}
pub(super) fn read<T: DeserializeOwned>(root: &Path, name: &str) -> T {
    private_root(root);
    metadata_name(name);
    let path = root.join(name);
    regular(&path);
    let file = File::open(&path).unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
    assert!(file.metadata().unwrap().len() <= 16 * 1024);
    let mut bytes = Vec::new();
    file.take(16 * 1024 + 1).read_to_end(&mut bytes).unwrap();
    assert!(!bytes.is_empty() && bytes.len() <= 16 * 1024);
    serde_json::from_slice(&bytes).unwrap()
}
