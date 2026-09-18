use std::collections::BTreeMap;

use runne_api::{
    WorkspaceChangeEntry, WorkspaceChangeKind, WorkspaceChangeListRequest, WorkspaceChangeSet,
    WorkspaceDiff, WorkspaceDiffHostError, WorkspaceDiffLine, WorkspaceDiffLineKind,
    WorkspaceDiffReadRequest,
};
use runne_application::ports::WorkspaceDiffProvider;
use runne_platform_desktop::RootHandleBrokerError;

const MAX_BASELINE_FILE_BYTES: usize = 256 * 1024;
const MAX_BASELINE_BYTES: usize = 8 * runne_api::MAX_WORKSPACE_DIFF_BYTES;
const MAX_BASELINE_ENTRIES: usize = runne_api::MAX_WORKSPACE_CHANGE_ENTRIES;

#[derive(Clone, Default)]
struct WorkspaceBaseline {
    files: BTreeMap<String, String>,
}

impl WorkspaceBaseline {
    fn capture(root: &VerifiedRootHandle) -> Result<Self, RootHandleBrokerError> {
        Ok(Self {
            files: capture_text_files(root)?,
        })
    }
}

impl WorkspaceDiffProvider for RootAdmissionGateway {
    fn list_changes(
        &self,
        principal: &str,
        request: &WorkspaceChangeListRequest,
    ) -> Result<WorkspaceChangeSet, WorkspaceDiffHostError> {
        (principal == PRINCIPAL)
            .then_some(())
            .ok_or(WorkspaceDiffHostError::Forbidden)?;
        self.with_active_root(request.workspace_id(), |active| {
            let current = capture_text_files(&active.handle).map_err(|_| WorkspaceDiffHostError::Unavailable)?;
            let mut entries = Vec::new();
            for (path, (before, after)) in changed_files(&active.baseline.files, &current) {
                let (kind, additions, deletions) = change_summary(before, after);
                entries.push(
                    WorkspaceChangeEntry::new(path, kind, additions, deletions)
                        .map_err(|_| WorkspaceDiffHostError::InvariantViolation)?,
                );
                if entries.len() == usize::from(request.limit()) {
                    break;
                }
            }
            WorkspaceChangeSet::new(entries).map_err(|_| WorkspaceDiffHostError::InvariantViolation)
        })
    }

    fn read_diff(
        &self,
        principal: &str,
        request: &WorkspaceDiffReadRequest,
    ) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
        (principal == PRINCIPAL)
            .then_some(())
            .ok_or(WorkspaceDiffHostError::Forbidden)?;
        self.with_active_root(request.workspace_id(), |active| {
            let current = capture_text_files(&active.handle).map_err(|_| WorkspaceDiffHostError::Unavailable)?;
            let before = active.baseline.files.get(request.relative_path()).map(String::as_str);
            let after = current.get(request.relative_path()).map(String::as_str);
            if before.is_none() && after.is_none() {
                return Err(WorkspaceDiffHostError::NotFound);
            }
            replacement_diff(request.relative_path(), before, after)
        })
    }
}

impl RootAdmissionGateway {
    fn with_active_root<T>(
        &self,
        workspace_id: runne_domain::id::WorkspaceId,
        operation: impl FnOnce(&ActiveRoot) -> Result<T, WorkspaceDiffHostError>,
    ) -> Result<T, WorkspaceDiffHostError> {
        let Some(authority) = &self.0 else {
            return Err(WorkspaceDiffHostError::Unavailable);
        };
        let result = authority
            .store
            .with_current_workspace_version(PRINCIPAL, workspace_id, |version| {
                let state = authority
                    .state
                    .lock()
                    .map_err(|_| runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
                let active = state
                    .active
                    .get(&workspace_id)
                    .filter(|active| active_root_is_current(version, active.version))
                    .ok_or(runne_application::ports::ProjectWorkspaceRepositoryError::Unavailable)?;
                Ok(operation(active))
            })
            ;
        match result {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(error),
            Err(error) => Err(match error {
                runne_application::ports::ProjectWorkspaceRepositoryError::NotFound => {
                    WorkspaceDiffHostError::NotFound
                }
                _ => WorkspaceDiffHostError::Unavailable,
            }),
        }
    }
}

fn capture_text_files(
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
                    if let Ok(content) = root.read_text_relative(
                        entry.relative_path(),
                        MAX_BASELINE_FILE_BYTES,
                    ) {
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

fn changed_files<'a>(
    before: &'a BTreeMap<String, String>,
    after: &'a BTreeMap<String, String>,
) -> impl Iterator<Item = (String, (Option<&'a String>, Option<&'a String>))> {
    before
        .keys()
        .chain(after.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .filter_map(move |path| {
            let pair = (before.get(path), after.get(path));
            (pair.0 != pair.1).then_some((path.clone(), pair))
        })
}

fn change_summary(before: Option<&String>, after: Option<&String>) -> (WorkspaceChangeKind, u32, u32) {
    let kind = match (before, after) {
        (None, Some(_)) => WorkspaceChangeKind::Added,
        (Some(_), None) => WorkspaceChangeKind::Deleted,
        (Some(_), Some(_)) => WorkspaceChangeKind::Modified,
        (None, None) => WorkspaceChangeKind::Modified,
    };
    let deletions = before.map_or(0, |value| value.lines().count());
    let additions = after.map_or(0, |value| value.lines().count());
    (kind, u32::try_from(additions).unwrap_or(u32::MAX), u32::try_from(deletions).unwrap_or(u32::MAX))
}

fn replacement_diff(
    path: &str,
    before: Option<&str>,
    after: Option<&str>,
) -> Result<WorkspaceDiff, WorkspaceDiffHostError> {
    let kind = match (before, after) {
        (None, Some(_)) => WorkspaceChangeKind::Added,
        (Some(_), None) => WorkspaceChangeKind::Deleted,
        _ => WorkspaceChangeKind::Modified,
    };
    let mut lines = Vec::new();
    let mut bytes = 0usize;
    let mut truncated = false;
    for (line_kind, content) in [
        (WorkspaceDiffLineKind::Removed, before),
        (WorkspaceDiffLineKind::Added, after),
    ] {
        if let Some(content) = content {
            for line in content.lines() {
                if lines.len() == runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK
                    || bytes.saturating_add(line.len()) > runne_api::MAX_WORKSPACE_DIFF_BYTES
                {
                    truncated = true;
                    break;
                }
                let value = WorkspaceDiffLine::new(line_kind, line)
                    .map_err(|_| WorkspaceDiffHostError::SizeLimit)?;
                bytes = bytes.saturating_add(value.text().len());
                lines.push(value);
            }
        }
        if truncated {
            break;
        }
    }
    let old_lines = lines.iter().filter(|line| line.kind() != WorkspaceDiffLineKind::Added).count();
    let new_lines = lines.iter().filter(|line| line.kind() != WorkspaceDiffLineKind::Removed).count();
    let hunk = runne_api::WorkspaceDiffHunk::new(
        1,
        u32::try_from(old_lines).map_err(|_| WorkspaceDiffHostError::SizeLimit)?,
        1,
        u32::try_from(new_lines).map_err(|_| WorkspaceDiffHostError::SizeLimit)?,
        lines,
    )
    .map_err(|_| WorkspaceDiffHostError::InvariantViolation)?;
    WorkspaceDiff::new(path, kind, vec![hunk], truncated)
        .map_err(|_| WorkspaceDiffHostError::InvariantViolation)
}

#[cfg(test)]
mod diff_tests {
    use super::{capture_text_files, replacement_diff};
    use runne_api::{WorkspaceChangeKind, WorkspaceDiffLineKind};
    use runne_platform_desktop::VerifiedRootHandle;

    #[test]
    fn replacement_diff_produces_bounded_structured_hunk() {
        let diff = replacement_diff("src/main.rs", Some("old\n"), Some("new\nline\n"))
            .expect("valid replacement");
        assert_eq!(diff.path(), "src/main.rs");
        assert_eq!(diff.kind(), WorkspaceChangeKind::Modified);
        assert_eq!(diff.hunks()[0].old_lines(), 1);
        assert_eq!(diff.hunks()[0].new_lines(), 2);
        assert_eq!(diff.hunks()[0].lines()[0].kind(), WorkspaceDiffLineKind::Removed);
        assert_eq!(diff.hunks()[0].lines()[2].text(), "line");
        assert!(!diff.truncated());
    }

    #[test]
    fn replacement_diff_truncates_at_the_per_hunk_limit() {
        let content = std::iter::repeat_n("line", runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK + 1)
            .collect::<Vec<_>>()
            .join("\n");
        let diff = replacement_diff("src/large.rs", Some(&content), None)
            .expect("bounded replacement");
        assert!(diff.truncated());
        assert_eq!(
            diff.hunks()[0].lines().len(),
            runne_api::MAX_WORKSPACE_DIFF_LINES_PER_HUNK
        );
    }

    #[test]
    fn baseline_capture_excludes_sensitive_and_binary_files() {
        let directory = tempfile::tempdir().expect("temporary workspace");
        std::fs::create_dir(directory.path().join("src")).expect("source directory");
        std::fs::write(directory.path().join("src/README.md"), "hello\n").expect("text file");
        std::fs::write(directory.path().join(".env"), "TOKEN=secret\n").expect("secret file");
        std::fs::write(directory.path().join("image.bin"), [0, 159, 146, 150]).expect("binary file");
        let canonical = std::fs::canonicalize(directory.path()).expect("canonical root path");
        let root = VerifiedRootHandle::open(&canonical).expect("verified root");
        let snapshot = capture_text_files(&root).expect("baseline snapshot");
        assert!(snapshot.contains_key("src/README.md"));
        assert!(!snapshot.contains_key(".env"));
        assert!(!snapshot.contains_key("image.bin"));
    }
}
