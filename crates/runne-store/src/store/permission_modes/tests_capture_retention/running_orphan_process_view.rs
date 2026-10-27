//! Actual own-process diagnostics, not authority over another process.
use super::clock::Deadline;
use super::io::bounded;
use super::model::pid;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ProcessView {
    pub process: u32,
    pub parent: u32,
    pub pid_namespace: String,
    pub mount_namespace: String,
    pub membership: String,
}

fn unique<'a>(text: &'a str, key: &str) -> &'a str {
    let values: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix(key))
        .collect();
    assert_eq!(values.len(), 1);
    values[0].trim()
}

fn link(path: &str, deadline: Deadline) -> String {
    deadline.check();
    // Deliberate own proc namespace magic links, never a foreign PID probe.
    let value = std::fs::read_link(path).unwrap();
    let text = value.to_str().unwrap();
    assert!(text.len() <= 64 && text.is_ascii());
    deadline.check();
    text.to_owned()
}

pub(super) fn current(deadline: Deadline) -> ProcessView {
    let status = bounded(Path::new("/proc/self/status"), 16384, deadline);
    let process = std::process::id();
    pid(process);
    assert_eq!(unique(&status, "Pid:").parse::<u32>().unwrap(), process);
    assert_eq!(unique(&status, "Tgid:").parse::<u32>().unwrap(), process);
    let parent = unique(&status, "PPid:").parse::<u32>().unwrap();
    pid(parent);
    let nspid: Vec<u32> = unique(&status, "NSpid:")
        .split_ascii_whitespace()
        .map(|text| text.parse().unwrap())
        .collect();
    assert_eq!(nspid, [process], "S/W/R use guest outer PID view");
    for field in ["Uid:", "Gid:"] {
        let ids: Vec<u32> = unique(&status, field)
            .split_ascii_whitespace()
            .map(|text| text.parse().unwrap())
            .collect();
        assert_eq!(ids, [1000; 4]);
    }
    assert!(unique(&status, "Groups:").is_empty());
    let membership =
        super::association::membership(&bounded(Path::new("/proc/self/cgroup"), 4096, deadline));
    ProcessView {
        process,
        parent,
        membership,
        pid_namespace: link("/proc/self/ns/pid", deadline),
        mount_namespace: link("/proc/self/ns/mnt", deadline),
    }
}
