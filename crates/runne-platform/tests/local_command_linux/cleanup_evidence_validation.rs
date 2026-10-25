use super::{Result, hex, refuse};
use serde::Serialize;
use std::collections::BTreeSet;
pub(super) const ENTRY_MAX: usize = 128;
pub(super) const INVENTORY_MAX: usize = 32768;
pub(super) const CONTROL_MAX: usize = 4096;
#[derive(Clone)]
pub(super) struct Expected {
    pub identity: [u8; 100],
    pub binding: [u8; 48],
    pub uid: u32,
    pub gid: u32,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
}
#[derive(Clone, Debug, Serialize)]
pub(super) struct Entry {
    pub name: String,
    pub kind: u8,
    pub ino: u64,
}
#[derive(Clone)]
pub(super) struct Observation {
    pub boot: [u8; 16],
    pub h: Stat,
    pub a: Stat,
    pub name: String,
    pub procs: Option<Vec<u8>>,
    pub procs_eof: bool,
    pub events: Vec<u8>,
    pub events_eof: bool,
    pub entries: Vec<Entry>,
    pub inventory_eof: bool,
    pub inventory_bytes: usize,
}
// Exact selected memory/pids cgroup ABI allowlist. New interfaces refuse pending review.
pub(super) fn allowed(name: &str) -> bool {
    matches!(
        name,
        "cgroup.controllers"
            | "cgroup.events"
            | "cgroup.freeze"
            | "cgroup.kill"
            | "cgroup.max.depth"
            | "cgroup.max.descendants"
            | "cgroup.procs"
            | "cgroup.pressure"
            | "cpu.pressure"
            | "io.pressure"
            | "cgroup.stat"
            | "cgroup.subtree_control"
            | "cgroup.threads"
            | "cgroup.type"
            | "cgroup.stat.local"
            | "cpu.stat"
            | "cpu.stat.local"
            | "irq.pressure"
            | "memory.current"
            | "memory.events"
            | "memory.events.local"
            | "memory.high"
            | "memory.low"
            | "memory.max"
            | "memory.min"
            | "memory.numa_stat"
            | "memory.oom.group"
            | "memory.peak"
            | "memory.pressure"
            | "memory.reclaim"
            | "memory.stat"
            | "memory.swap.current"
            | "memory.swap.events"
            | "memory.swap.high"
            | "memory.swap.max"
            | "memory.swap.peak"
            | "memory.zswap.current"
            | "memory.zswap.max"
            | "memory.zswap.writeback"
            | "pids.current"
            | "pids.events"
            | "pids.events.local"
            | "pids.max"
            | "pids.peak"
    )
}
pub(super) fn identity(expected: &Expected, o: &Observation) -> Result<()> {
    let b = &expected.identity;
    let n = |start| u64::from_be_bytes(b[start..start + 8].try_into().expect("fixed field"));
    if &b[..4] != b"RMA1"
        || b[4..20] != o.boot
        || o.boot == [0; 16]
        || b[52..] != expected.binding
        || o.name != format!("runne-{}", hex(&expected.binding))
        || (o.h.dev, o.h.ino, o.a.dev, o.a.ino) != (n(20), n(28), n(36), n(44))
        || o.h.ino == 0
        || o.a.ino == 0
        || [o.h.uid, o.a.uid] != [expected.uid; 2]
        || [o.h.gid, o.a.gid] != [expected.gid; 2]
    {
        return Err(refuse());
    }
    Ok(())
}
pub(super) fn events(raw: &[u8]) -> Result<()> {
    if raw.is_empty() || raw.len() > CONTROL_MAX || !raw.ends_with(b"\n") {
        return Err(refuse());
    }
    let text = std::str::from_utf8(raw).map_err(|_| refuse())?;
    let mut seen = BTreeSet::new();
    for line in text.split_terminator('\n') {
        let (key, value) = line.split_once(' ').ok_or_else(refuse)?;
        if !seen.insert(key)
            || !matches!(key, "populated" | "frozen")
            || !matches!(value, "0" | "1")
            || key == "populated" && value != "0"
        {
            return Err(refuse());
        }
    }
    if !seen.contains("populated") {
        return Err(refuse());
    }
    Ok(())
}
pub(super) fn validate(expected: &Expected, o: &Observation) -> Result<()> {
    identity(expected, o)?;
    if !o.events_eof
        || !o.procs_eof
        || o.procs.as_deref() != Some(b"".as_slice())
        || !o.inventory_eof
        || o.entries.len() > ENTRY_MAX
        || o.inventory_bytes > INVENTORY_MAX
    {
        return Err(refuse());
    }
    events(&o.events)?;
    let mut seen = BTreeSet::new();
    for entry in &o.entries {
        if entry.name.len() > 255 || entry.ino == 0 || !seen.insert(entry.name.as_str()) {
            return Err(refuse());
        }
        match entry.name.as_str() {
            "." if entry.kind == libc::DT_DIR && entry.ino == o.a.ino => (),
            ".." if entry.kind == libc::DT_DIR && entry.ino == o.h.ino => (),
            name if allowed(name) && entry.kind == libc::DT_REG => (),
            _ => return Err(refuse()),
        }
    }
    for name in [".", "..", "cgroup.procs", "cgroup.events"] {
        if !seen.contains(name) {
            return Err(refuse());
        }
    }
    Ok(())
}
