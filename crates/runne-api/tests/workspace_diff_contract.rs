use runne_api::{
    WorkspaceChangeEntry, WorkspaceChangeKind, WorkspaceChangeSet, WorkspaceDiff,
    WorkspaceDiffHunk, WorkspaceDiffLine, WorkspaceDiffLineKind,
};

#[test]
fn change_set_is_sorted_unique_and_path_bound() {
    let first = WorkspaceChangeEntry::new("src/a.rs", WorkspaceChangeKind::Modified, 2, 1)
        .expect("valid change");
    let second = WorkspaceChangeEntry::new("src/b.rs", WorkspaceChangeKind::Added, 4, 0)
        .expect("valid change");
    assert!(WorkspaceChangeSet::new(vec![first.clone(), second.clone()]).is_ok());
    assert!(WorkspaceChangeSet::new(vec![second, first]).is_err());
    assert!(WorkspaceChangeEntry::new("/etc/passwd", WorkspaceChangeKind::Modified, 1, 1).is_err());
    assert!(
        WorkspaceChangeEntry::new("src/../secret", WorkspaceChangeKind::Modified, 1, 1).is_err()
    );
}

#[test]
fn diff_hunk_counts_lines_and_rejects_unsafe_or_oversized_content() {
    let lines = vec![
        WorkspaceDiffLine::new(WorkspaceDiffLineKind::Context, "same").expect("line"),
        WorkspaceDiffLine::new(WorkspaceDiffLineKind::Removed, "old").expect("line"),
        WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "new").expect("line"),
    ];
    assert!(WorkspaceDiffHunk::new(1, 2, 1, 2, lines).is_ok());
    assert!(
        WorkspaceDiffHunk::new(
            1,
            1,
            1,
            2,
            vec![WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "new").unwrap()]
        )
        .is_err()
    );
    assert!(WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "<script>").is_ok());
    assert!(WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "bad\nline").is_err());
    assert!(WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "bad\u{7f}line").is_err());

    let hunk = WorkspaceDiffHunk::new(
        1,
        2,
        1,
        2,
        vec![
            WorkspaceDiffLine::new(WorkspaceDiffLineKind::Context, "same").unwrap(),
            WorkspaceDiffLine::new(WorkspaceDiffLineKind::Removed, "old").unwrap(),
            WorkspaceDiffLine::new(WorkspaceDiffLineKind::Added, "new").unwrap(),
        ],
    )
    .unwrap();
    assert!(
        WorkspaceDiff::new(
            "src/main.rs",
            WorkspaceChangeKind::Modified,
            vec![hunk],
            false
        )
        .is_ok()
    );
}

#[test]
fn diff_hunk_rejects_unbounded_empty_line_payloads() {
    let lines = (0..70_000)
        .map(|_| WorkspaceDiffLine::new(WorkspaceDiffLineKind::Context, ""))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(WorkspaceDiffHunk::new(1, 70_000, 1, 70_000, lines).is_err());
}
