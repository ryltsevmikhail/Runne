//! Pure diagnostic path derivation; never an area or process authority.
//! Derived from SOURCE8416 platform current.rs and identity.rs encoding.
use runne_platform::process_managed_area::ManagedAreaIdentity;
use std::path::{Component, Path, PathBuf};

pub(super) struct AreaPath {
    pub root: PathBuf,
    pub directory: PathBuf,
    pub membership: String,
    pub root_device: u64,
    pub root_inode: u64,
    pub area_device: u64,
    pub area_inode: u64,
}
fn safe(path: &Path) {
    assert!(path.is_absolute());
    assert!(
        path.components()
            .all(|c| matches!(c, Component::RootDir | Component::Normal(_)))
    );
    let text = path.to_str().unwrap();
    assert!(!text.contains('\0'));
    assert!(!text.split('/').any(|s| matches!(s, "." | "..")));
}
fn decode(raw: &str) -> String {
    assert!(raw.len() <= 4096);
    let mut bytes = Vec::new();
    let input = raw.as_bytes();
    let mut i = 0;
    while i < input.len() {
        if input[i] != b'\\' {
            bytes.push(input[i]);
            i += 1;
            continue;
        }
        let digits = input.get(i + 1..i + 4).expect("full mount escape");
        assert!(digits.iter().all(|d| matches!(d, b'0'..=b'7')));
        let value = u16::from(digits[0] - b'0') * 64
            + u16::from(digits[1] - b'0') * 8
            + u16::from(digits[2] - b'0');
        bytes.push(u8::try_from(value).expect("byte mount escape"));
        i += 4;
    }
    String::from_utf8(bytes).unwrap()
}
pub(super) fn locate(
    identity: &ManagedAreaIdentity,
    current_membership: &str,
    mountinfo: &str,
) -> AreaPath {
    assert!(current_membership.len() <= 4096 && mountinfo.len() <= 128 * 1024);
    let lines: Vec<_> = current_membership.lines().collect();
    assert_eq!(lines.len(), 1, "guest unified hierarchy only");
    let group = Path::new(lines[0].strip_prefix("0::").unwrap());
    safe(group);
    let mut matches = Vec::new();
    for line in mountinfo.lines() {
        let (left, right) = line.split_once(" - ").expect("mountinfo separator");
        if right.split_ascii_whitespace().next() != Some("cgroup2") {
            continue;
        }
        let fields: Vec<_> = left.split_ascii_whitespace().collect();
        assert!(fields.len() >= 6);
        let root = PathBuf::from(decode(fields[3]));
        let point = PathBuf::from(decode(fields[4]));
        safe(&root);
        safe(&point);
        if let Ok(relative) = group.strip_prefix(&root) {
            matches.push(point.join(relative));
        }
    }
    assert_eq!(matches.len(), 1, "unique exact cgroup2 mount");
    let root = matches.pop().unwrap();
    safe(&root);
    let bytes = identity.to_bytes();
    let decoded = ManagedAreaIdentity::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    // Whole identity is100 bytes; basename uses only task/attempt/nonce48bytes.
    let basename = format!("runne-{}", hex::encode(&bytes[52..100]));
    assert_eq!(basename.len(), 102);
    let directory = root.join(&basename);
    safe(&directory);
    let membership = group.join(&basename).to_str().unwrap().to_owned();
    let number =
        |range: std::ops::Range<usize>| u64::from_be_bytes(bytes[range].try_into().unwrap());
    AreaPath {
        root,
        directory,
        membership,
        root_device: number(20..28),
        root_inode: number(28..36),
        area_device: number(36..44),
        area_inode: number(44..52),
    }
}
