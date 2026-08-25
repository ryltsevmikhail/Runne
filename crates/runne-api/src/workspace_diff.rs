//! Bounded, structured Workspace change and diff contracts.

pub const MAX_WORKSPACE_CHANGE_ENTRIES: usize = 1_000;
pub const MAX_WORKSPACE_DIFF_HUNKS: usize = 512;
pub const MAX_WORKSPACE_DIFF_LINES_PER_HUNK: usize = 16_384;
pub const MAX_WORKSPACE_DIFF_LINES: usize = 65_536;
pub const MAX_WORKSPACE_DIFF_LINE_BYTES: usize = 16 * 1024;
pub const MAX_WORKSPACE_DIFF_BYTES: usize = 1_048_576;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceChangeKind {
    Added,
    Modified,
    Deleted,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceChangeEntry {
    path: String,
    kind: WorkspaceChangeKind,
    additions: u32,
    deletions: u32,
}

impl WorkspaceChangeEntry {
    pub fn new(
        path: impl Into<String>,
        kind: WorkspaceChangeKind,
        additions: u32,
        deletions: u32,
    ) -> Result<Self, WorkspaceDiffError> {
        let path = validate_path(path.into())?;
        Ok(Self {
            path,
            kind,
            additions,
            deletions,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub const fn kind(&self) -> WorkspaceChangeKind {
        self.kind
    }
    #[must_use]
    pub const fn additions(&self) -> u32 {
        self.additions
    }
    #[must_use]
    pub const fn deletions(&self) -> u32 {
        self.deletions
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceChangeSet {
    entries: Vec<WorkspaceChangeEntry>,
}

impl WorkspaceChangeSet {
    pub fn new(entries: Vec<WorkspaceChangeEntry>) -> Result<Self, WorkspaceDiffError> {
        if entries.len() > MAX_WORKSPACE_CHANGE_ENTRIES
            || !entries
                .windows(2)
                .all(|pair| pair[0].path.as_str() < pair[1].path.as_str())
        {
            return Err(WorkspaceDiffError::InvariantViolation);
        }
        Ok(Self { entries })
    }

    #[must_use]
    pub fn entries(&self) -> &[WorkspaceChangeEntry] {
        &self.entries
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceDiffLineKind {
    Context,
    Added,
    Removed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffLine {
    kind: WorkspaceDiffLineKind,
    text: String,
}

impl WorkspaceDiffLine {
    pub fn new(
        kind: WorkspaceDiffLineKind,
        text: impl Into<String>,
    ) -> Result<Self, WorkspaceDiffError> {
        let text = text.into();
        if text.len() > MAX_WORKSPACE_DIFF_LINE_BYTES
            || text
                .bytes()
                .any(|byte| byte == b'\n' || byte == b'\r' || !valid_text_byte(byte))
        {
            return Err(WorkspaceDiffError::InvalidLine);
        }
        Ok(Self { kind, text })
    }

    #[must_use]
    pub const fn kind(&self) -> WorkspaceDiffLineKind {
        self.kind
    }
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiffHunk {
    old_start: u32,
    old_lines: u32,
    new_start: u32,
    new_lines: u32,
    lines: Vec<WorkspaceDiffLine>,
}

impl WorkspaceDiffHunk {
    pub fn new(
        old_start: u32,
        old_lines: u32,
        new_start: u32,
        new_lines: u32,
        lines: Vec<WorkspaceDiffLine>,
    ) -> Result<Self, WorkspaceDiffError> {
        let old_count = lines
            .iter()
            .filter(|line| line.kind != WorkspaceDiffLineKind::Added)
            .count();
        let new_count = lines
            .iter()
            .filter(|line| line.kind != WorkspaceDiffLineKind::Removed)
            .count();
        if lines.len() > MAX_WORKSPACE_DIFF_LINES_PER_HUNK
            || old_start == 0
            || new_start == 0
            || old_count != old_lines as usize
            || new_count != new_lines as usize
        {
            return Err(WorkspaceDiffError::InvariantViolation);
        }
        Ok(Self {
            old_start,
            old_lines,
            new_start,
            new_lines,
            lines,
        })
    }

    #[must_use]
    pub const fn old_start(&self) -> u32 {
        self.old_start
    }
    #[must_use]
    pub const fn old_lines(&self) -> u32 {
        self.old_lines
    }
    #[must_use]
    pub const fn new_start(&self) -> u32 {
        self.new_start
    }
    #[must_use]
    pub const fn new_lines(&self) -> u32 {
        self.new_lines
    }
    #[must_use]
    pub fn lines(&self) -> &[WorkspaceDiffLine] {
        &self.lines
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkspaceDiff {
    path: String,
    kind: WorkspaceChangeKind,
    hunks: Vec<WorkspaceDiffHunk>,
    truncated: bool,
}

impl WorkspaceDiff {
    pub fn new(
        path: impl Into<String>,
        kind: WorkspaceChangeKind,
        hunks: Vec<WorkspaceDiffHunk>,
        truncated: bool,
    ) -> Result<Self, WorkspaceDiffError> {
        let path = validate_path(path.into())?;
        if hunks.len() > MAX_WORKSPACE_DIFF_HUNKS
            || !hunks.windows(2).all(|pair| {
                (pair[0].old_start(), pair[0].new_start())
                    < (pair[1].old_start(), pair[1].new_start())
            })
        {
            return Err(WorkspaceDiffError::InvariantViolation);
        }
        let line_count = hunks
            .iter()
            .try_fold(0_usize, |total, hunk| total.checked_add(hunk.lines.len()))
            .ok_or(WorkspaceDiffError::SizeLimit)?;
        let bytes = hunks
            .iter()
            .flat_map(WorkspaceDiffHunk::lines)
            .try_fold(0_usize, |total, line| total.checked_add(line.text.len()))
            .ok_or(WorkspaceDiffError::SizeLimit)?;
        if line_count > MAX_WORKSPACE_DIFF_LINES || bytes > MAX_WORKSPACE_DIFF_BYTES {
            return Err(WorkspaceDiffError::SizeLimit);
        }
        Ok(Self {
            path,
            kind,
            hunks,
            truncated,
        })
    }

    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }
    #[must_use]
    pub const fn kind(&self) -> WorkspaceChangeKind {
        self.kind
    }
    #[must_use]
    pub fn hunks(&self) -> &[WorkspaceDiffHunk] {
        &self.hunks
    }
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkspaceDiffError {
    InvalidPath,
    InvalidLine,
    SizeLimit,
    InvariantViolation,
}

pub(crate) fn validate_path(path: String) -> Result<String, WorkspaceDiffError> {
    if path.is_empty()
        || path.len() > 4_096
        || path.starts_with('/')
        || path.contains('\\')
        || path.bytes().any(|byte| byte == 0 || byte < 0x20)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(WorkspaceDiffError::InvalidPath);
    }
    Ok(path)
}

const fn valid_text_byte(byte: u8) -> bool {
    byte != 0x7f && (byte == b'\t' || byte >= 0x20)
}
