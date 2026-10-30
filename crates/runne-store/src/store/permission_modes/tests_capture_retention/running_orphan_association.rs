//! Guest-only diagnostics. Never an authority to signal, wait, or release GO.
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path};
use std::time::Instant;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Spawner {
    pub writer: u32,
    pub tid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Association {
    pub spawner: Spawner,
    pub native: u32,
    pub start_ticks: u64,
    pub nspid: Vec<u32>,
    pub membership: String,
}
fn number(text: &str) -> u64 {
    assert!(!text.is_empty() && text.len() <= 20);
    assert!(text.bytes().all(|c| c.is_ascii_digit()));
    assert!(!text.starts_with('0'));
    text.parse().expect("checked positive decimal")
}
fn pid(text: &str) -> u32 {
    let value = number(text);
    assert!(value > 1 && value <= i32::MAX as u64);
    value as u32
}
fn bounded(path: &Path, cap: usize, deadline: Instant) -> String {
    assert!(Instant::now() < deadline);
    let mut file: File = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .expect("exact proc diagnostic must be readable");
    assert!(file.metadata().unwrap().is_file());
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        assert!(Instant::now() < deadline);
        let remaining = cap + 1 - bytes.len();
        let size = remaining.min(chunk.len());
        let n = match file.read(&mut chunk[..size]) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => panic!("exact proc diagnostic read failed: {e}"),
        };
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..n]);
        assert!(bytes.len() <= cap, "proc diagnostic cap exceeded");
    }
    assert!(Instant::now() < deadline);
    String::from_utf8(bytes).unwrap()
}
impl Spawner {
    pub(super) fn current(deadline: Instant) -> Self {
        assert!(Instant::now() < deadline);
        // Deliberate kernel proc magic link; not an untrusted case-root path.
        let link = std::fs::read_link("/proc/thread-self").unwrap();
        let text = link.to_str().unwrap();
        let parts: Vec<_> = text.split('/').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "task");
        let value = Self {
            writer: pid(parts[0]),
            tid: pid(parts[2]),
        };
        assert_eq!(value.writer, std::process::id());
        assert!(Instant::now() < deadline);
        value
    }
    pub(super) fn children(&self, deadline: Instant) -> Vec<u32> {
        let path = format!("/proc/{}/task/{}/children", self.writer, self.tid);
        let text = bounded(Path::new(&path), 4096, deadline);
        let values: Vec<_> = text.split_ascii_whitespace().map(pid).collect();
        assert!(values.len() <= 1, "closed no-fork workload");
        values
    }
}
fn stat_identity(text: &str, expected: u32, writer: u32) -> u64 {
    assert!(!text.is_empty(), "required proc stat");
    let (head, _) = text.split_once(" (").expect("proc stat header");
    assert_eq!(pid(head), expected);
    let end = text.rfind(") ").expect("last comm terminator");
    let fields: Vec<_> = text[end + 2..].split_ascii_whitespace().collect();
    assert!(fields.len() >= 20 && fields.len() <= 64);
    assert!(matches!(
        fields[0],
        "R" | "S" | "D" | "T" | "t" | "I" | "W" | "P" | "K"
    ));
    assert_eq!(pid(fields[1]), writer);
    number(fields[19])
}
fn status_pids(text: &str, expected: u32, writer: u32) -> Vec<u32> {
    fn unique<'a>(text: &'a str, key: &str) -> &'a str {
        let values: Vec<_> = text
            .lines()
            .filter_map(|line| line.strip_prefix(key))
            .collect();
        assert_eq!(values.len(), 1);
        values[0].trim()
    }
    assert_eq!(pid(unique(text, "Pid:")), expected);
    assert_eq!(pid(unique(text, "Tgid:")), expected);
    assert_eq!(pid(unique(text, "PPid:")), writer);
    let values: Vec<_> = unique(text, "NSpid:")
        .split_ascii_whitespace()
        .map(|s| u32::try_from(number(s)).unwrap())
        .collect();
    assert_eq!(
        values.len(),
        2,
        "one new PID namespace below guest outer view"
    );
    assert_eq!(values[0], expected);
    assert_eq!(values[1], 1);
    values
}
pub(super) fn membership(text: &str) -> String {
    let lines: Vec<_> = text.lines().collect();
    assert_eq!(lines.len(), 1, "single unified hierarchy");
    let value = lines[0].strip_prefix("0::").unwrap();
    assert!(value.starts_with('/') && value.len() <= 4096);
    assert!(value.bytes().all(|b| b.is_ascii_graphic()));
    assert!(!value.contains('\\') && !value.contains('\0'));
    for c in Path::new(value).components() {
        assert!(matches!(c, Component::RootDir | Component::Normal(_)));
    }
    assert!(!value.split('/').any(|s| matches!(s, "." | "..")));
    value.to_owned()
}
pub(super) fn observe(
    spawner: &Spawner,
    expected_native: u32,
    expected_membership: &str,
    outer_pids: &[u32],
    deadline: Instant,
) -> Association {
    assert!(expected_native > 1 && expected_native <= i32::MAX as u32);
    assert!(!outer_pids.contains(&expected_native));
    assert_ne!(expected_native, spawner.writer);
    assert_eq!(spawner.children(deadline), [expected_native]);
    let prefix = format!("/proc/{expected_native}");
    let first = bounded(Path::new(&format!("{prefix}/stat")), 4096, deadline);
    let start_ticks = stat_identity(&first, expected_native, spawner.writer);
    let status = bounded(Path::new(&format!("{prefix}/status")), 16384, deadline);
    let nspid = status_pids(&status, expected_native, spawner.writer);
    let cg = bounded(Path::new(&format!("{prefix}/cgroup")), 4096, deadline);
    let actual_membership = membership(&cg);
    assert_eq!(actual_membership, expected_membership);
    let second = bounded(Path::new(&format!("{prefix}/stat")), 4096, deadline);
    assert_eq!(
        stat_identity(&second, expected_native, spawner.writer),
        start_ticks
    );
    assert_eq!(spawner.children(deadline), [expected_native]);
    Association {
        spawner: spawner.clone(),
        native: expected_native,
        start_ticks,
        nspid,
        membership: actual_membership,
    }
}

#[cfg(test)]
#[path = "running_orphan_association_tests.rs"]
mod tests;
