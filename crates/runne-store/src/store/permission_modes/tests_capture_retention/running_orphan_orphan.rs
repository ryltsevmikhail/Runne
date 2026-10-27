//! Diagnostic orphan identity joined to the unchanged public held area.
//! Never signal/reap via PID; only the collector owns lost native waitpid.
use super::{
    area_path,
    association::{self, Association},
    context::CaseContext,
    held_area::HeldAreaReader,
    io::bounded,
    metadata::Area,
};
use std::path::Path;

fn decimal(text: &str) -> u64 {
    assert!(!text.is_empty() && text.len() <= 20 && !text.starts_with('0'));
    assert!(text.bytes().all(|b| b.is_ascii_digit()));
    text.parse().unwrap()
}
fn field<'a>(text: &'a str, prefix: &str) -> &'a str {
    let values: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .collect();
    assert_eq!(values.len(), 1);
    values[0].trim()
}
fn stat(text: &str, original: &Association, collector: u32) {
    assert_eq!(
        decimal(text.split_once(" (").unwrap().0),
        original.native as u64
    );
    let end = text.rfind(") ").unwrap();
    let values: Vec<_> = text[end + 2..].split_ascii_whitespace().collect();
    assert!((20..=64).contains(&values.len()));
    assert!(matches!(
        values[0],
        "R" | "S" | "D" | "T" | "t" | "I" | "W" | "P" | "K"
    ));
    assert_eq!(decimal(values[1]), collector as u64);
    assert_eq!(decimal(values[19]), original.start_ticks);
}

pub(super) fn observe(
    context: &CaseContext,
    saved: &Area,
    held: &HeldAreaReader,
    original: &Association,
) {
    held.check(context);
    assert!(held.area().is_populated().unwrap());
    let current = bounded(Path::new("/proc/self/cgroup"), 4096, context.deadline);
    assert_eq!(association::membership(&current), context.record.membership);
    let mounts = bounded(Path::new("/proc/self/mountinfo"), 65536, context.deadline);
    let path = area_path::locate(&saved.area_identity(), &current, &mounts);
    assert_eq!(path.membership, original.membership);
    assert_eq!(held.area().identity().to_bytes().as_slice(), saved.area);
    let members = || {
        let text = bounded(&path.directory.join("cgroup.procs"), 4096, context.deadline);
        assert_eq!(
            text.split_ascii_whitespace().collect::<Vec<_>>(),
            [original.native.to_string()]
        );
    };
    members();
    let prefix = format!("/proc/{}", original.native);
    let stat_path = format!("{prefix}/stat");
    stat(
        &bounded(Path::new(&stat_path), 4096, context.deadline),
        original,
        context.record.collector,
    );
    let text = bounded(
        Path::new(&format!("{prefix}/status")),
        16384,
        context.deadline,
    );
    for key in ["Pid:", "Tgid:"] {
        assert_eq!(decimal(field(&text, key)), original.native as u64);
    }
    assert_eq!(
        decimal(field(&text, "PPid:")),
        context.record.collector as u64
    );
    assert_eq!(
        field(&text, "NSpid:")
            .split_ascii_whitespace()
            .map(decimal)
            .collect::<Vec<_>>(),
        [original.native as u64, 1]
    );
    let membership = bounded(
        Path::new(&format!("{prefix}/cgroup")),
        4096,
        context.deadline,
    );
    assert_eq!(association::membership(&membership), original.membership);
    stat(
        &bounded(Path::new(&stat_path), 4096, context.deadline),
        original,
        context.record.collector,
    );
    members();
    held.check(context);
    assert!(held.area().is_populated().unwrap());
    context.deadline.check();
}
