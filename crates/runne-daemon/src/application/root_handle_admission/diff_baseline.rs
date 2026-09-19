//! Baseline snapshot of one admitted root plus the shared frozen-deny path
//! check used by every workspace content channel (plan 18 §T1, inventory §E/§G3).

use std::collections::{BTreeMap, BTreeSet};

use runne_api::WorkspaceChangeKind;
use runne_platform_desktop::{RootFileKind, RootHandleBrokerError, VerifiedRootHandle};

const MAX_BASELINE_FILE_BYTES: usize = 256 * 1024;
const MAX_BASELINE_BYTES: usize = 8 * runne_api::MAX_WORKSPACE_DIFF_BYTES;
const MAX_BASELINE_ENTRIES: usize = runne_api::MAX_WORKSPACE_CHANGE_ENTRIES;

/// Diff baseline of one admitted root.
///
/// `Unverified` is an explicit denied state: no capture was approved by the
/// trust gate at bind time, so the workspace was never pre-read and diffs
/// stay denied rather than fabricating a plausible empty-baseline diff.
#[derive(Clone)]
pub(super) enum WorkspaceBaseline {
    /// Approved capture taken while trust admitted the FilesList channel.
    Captured { files: BTreeMap<String, String> },
    /// No approved capture exists (untrusted or fail-closed bind).
    Unverified,
}

impl WorkspaceBaseline {
    pub(super) fn capture(root: &VerifiedRootHandle) -> Result<Self, RootHandleBrokerError> {
        Ok(Self::Captured {
            files: capture_text_files(root)?,
        })
    }

    pub(super) fn unverified() -> Self {
        Self::Unverified
    }

    pub(super) fn files(&self) -> Option<&BTreeMap<String, String>> {
        match self {
            Self::Captured { files } => Some(files),
            Self::Unverified => None,
        }
    }
}

/// Frozen deny-policy check (inventory §G3): supersedes the legacy suffix
/// denylist at wiring time. The empty path (a root listing) names no file;
/// ambiguous shapes fail closed.
pub(super) fn sensitive_path(path: &str) -> bool {
    !path.is_empty()
        && runne_security::project_trust_policy::normalize_source_path(path)
            .map(|components| {
                runne_security::project_trust_policy::denied_by_frozen_set(&components)
            })
            .unwrap_or(true)
}

pub(super) fn capture_text_files(
    root: &VerifiedRootHandle,
) -> Result<BTreeMap<String, String>, RootHandleBrokerError> {
    let mut directories = vec![String::new()];
    let mut files = BTreeMap::new();
    let mut bytes = 0usize;
    let mut entries_seen = 0usize;
    while let Some(directory) = directories.pop() {
        let entries = if directory.is_empty() {
            root.list_root(runne_api::MAX_WORKSPACE_CHANGE_ENTRIES + 1)?
        } else {
            root.list_relative(&directory, runne_api::MAX_WORKSPACE_CHANGE_ENTRIES + 1)?
        };
        for entry in entries {
            entries_seen = entries_seen
                .checked_add(1)
                .ok_or(RootHandleBrokerError::Rejected)?;
            if entries_seen > MAX_BASELINE_ENTRIES {
                return Err(RootHandleBrokerError::Rejected);
            }
            if sensitive_path(entry.relative_path()) {
                continue;
            }
            match entry.kind() {
                RootFileKind::Directory => directories.push(entry.relative_path().to_owned()),
                RootFileKind::File if entry.size_bytes() <= MAX_BASELINE_FILE_BYTES as u64 => {
                    if let Ok(content) =
                        root.read_text_relative(entry.relative_path(), MAX_BASELINE_FILE_BYTES)
                    {
                        let next = bytes.saturating_add(content.len());
                        if next <= MAX_BASELINE_BYTES {
                            bytes = next;
                            files.insert(entry.relative_path().to_owned(), content);
                        }
                    }
                }
                RootFileKind::File => {}
            }
        }
    }
    Ok(files)
}

pub(super) fn changed_files<'a>(
    before: &'a BTreeMap<String, String>,
    after: &'a BTreeMap<String, String>,
) -> impl Iterator<Item = (String, (Option<&'a String>, Option<&'a String>))> {
    before
        .keys()
        .chain(after.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter_map(move |path| {
            let pair = (before.get(path), after.get(path));
            (pair.0 != pair.1).then_some((path.clone(), pair))
        })
}

pub(super) fn change_summary(
    before: Option<&String>,
    after: Option<&String>,
) -> (WorkspaceChangeKind, u32, u32) {
    let kind = match (before, after) {
        (None, Some(_)) => WorkspaceChangeKind::Added,
        (Some(_), None) => WorkspaceChangeKind::Deleted,
        (Some(_), Some(_)) => WorkspaceChangeKind::Modified,
        (None, None) => WorkspaceChangeKind::Modified,
    };
    let deletions = before.map_or(0, |value| value.lines().count());
    let additions = after.map_or(0, |value| value.lines().count());
    (
        kind,
        u32::try_from(additions).unwrap_or(u32::MAX),
        u32::try_from(deletions).unwrap_or(u32::MAX),
    )
}

#[cfg(test)]
mod tests {
    use super::{capture_text_files, sensitive_path};
    use runne_platform_desktop::VerifiedRootHandle;

    #[test]
    fn baseline_capture_excludes_sensitive_and_binary_files() {
        let directory = tempfile::tempdir().expect("temporary workspace");
        std::fs::create_dir(directory.path().join("src")).expect("source directory");
        std::fs::write(directory.path().join("src/README.md"), "hello\n").expect("text file");
        std::fs::write(directory.path().join(".env"), "TOKEN=secret\n").expect("secret file");
        std::fs::write(directory.path().join("image.bin"), [0, 159, 146, 150])
            .expect("binary file");
        let canonical = std::fs::canonicalize(directory.path()).expect("canonical root path");
        let root = VerifiedRootHandle::open(&canonical).expect("verified root");
        let snapshot = capture_text_files(&root).expect("baseline snapshot");
        assert!(snapshot.contains_key("src/README.md"));
        assert!(!snapshot.contains_key(".env"));
        assert!(!snapshot.contains_key("image.bin"));
    }

    #[test]
    fn sensitive_paths_fail_closed_on_ambiguous_shapes() {
        assert!(sensitive_path(".env"));
        assert!(sensitive_path(".ENV"));
        assert!(!sensitive_path("notes/plan.md"));
        assert!(!sensitive_path(""));
        assert!(sensitive_path("a/../.env"));
        assert!(sensitive_path("notes\\plan.md"));
    }
}
