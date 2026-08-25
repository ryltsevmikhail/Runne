use runne_api::{
    WorkspaceChangeKind, WorkspaceChangeSet, WorkspaceDiff, WorkspaceDiffHunk, WorkspaceDiffLine,
    WorkspaceDiffLineKind,
};
use serde::Serialize;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ChangeSetWire {
    items: Vec<ChangeEntryWire>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChangeEntryWire {
    path: String,
    kind: &'static str,
    additions: u32,
    deletions: u32,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DiffWire {
    path: String,
    kind: &'static str,
    hunks: Vec<HunkWire>,
    truncated: bool,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct HunkWire {
    old_start: u32,
    old_lines: u32,
    new_start: u32,
    new_lines: u32,
    lines: Vec<LineWire>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LineWire {
    kind: &'static str,
    text: String,
}

impl From<WorkspaceChangeSet> for ChangeSetWire {
    fn from(value: WorkspaceChangeSet) -> Self {
        Self {
            items: value
                .entries()
                .iter()
                .map(|item| ChangeEntryWire {
                    path: item.path().into(),
                    kind: change_kind(item.kind()),
                    additions: item.additions(),
                    deletions: item.deletions(),
                })
                .collect(),
        }
    }
}

impl From<WorkspaceDiff> for DiffWire {
    fn from(value: WorkspaceDiff) -> Self {
        Self {
            path: value.path().into(),
            kind: change_kind(value.kind()),
            hunks: value.hunks().iter().map(HunkWire::from).collect(),
            truncated: value.truncated(),
        }
    }
}

impl From<&WorkspaceDiffHunk> for HunkWire {
    fn from(value: &WorkspaceDiffHunk) -> Self {
        Self {
            old_start: value.old_start(),
            old_lines: value.old_lines(),
            new_start: value.new_start(),
            new_lines: value.new_lines(),
            lines: value.lines().iter().map(LineWire::from).collect(),
        }
    }
}

impl From<&WorkspaceDiffLine> for LineWire {
    fn from(value: &WorkspaceDiffLine) -> Self {
        Self {
            kind: line_kind(value.kind()),
            text: value.text().into(),
        }
    }
}

fn change_kind(value: WorkspaceChangeKind) -> &'static str {
    match value {
        WorkspaceChangeKind::Added => "added",
        WorkspaceChangeKind::Modified => "modified",
        WorkspaceChangeKind::Deleted => "deleted",
    }
}
fn line_kind(value: WorkspaceDiffLineKind) -> &'static str {
    match value {
        WorkspaceDiffLineKind::Context => "context",
        WorkspaceDiffLineKind::Added => "added",
        WorkspaceDiffLineKind::Removed => "removed",
    }
}
