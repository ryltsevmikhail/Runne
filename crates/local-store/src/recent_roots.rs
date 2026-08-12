use super::{LocalStore, OptionalExtension, params};

const MAX_DISPLAY_NAME_BYTES: usize = 256;
const MAX_NATIVE_ROOT_METADATA_BYTES: usize = 4096;
const MAX_SAFE_TIMESTAMP: i64 = 9_007_199_254_740_991;

/// Renderer-safe summary of one canonical recent root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecentRoot {
    project_id: CanonicalProjectId,
    workspace_id: CanonicalWorkspaceId,
    display_name: RecentRootDisplayName,
    last_opened_at: i64,
}

impl RecentRoot {
    /// Returns the canonical Project ID.
    #[must_use]
    pub fn project_id(&self) -> &str {
        self.project_id.as_str()
    }

    /// Returns the canonical Workspace ID.
    #[must_use]
    pub fn workspace_id(&self) -> &str {
        self.workspace_id.as_str()
    }

    /// Returns the bounded renderer-visible display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        self.display_name.as_str()
    }

    /// Returns the Unix-millisecond recency timestamp.
    #[must_use]
    pub const fn last_opened_at(&self) -> i64 {
        self.last_opened_at
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RecentRootError {
    #[error("recent root is invalid")]
    Invalid,
    #[error("recent root storage is corrupt")]
    Corrupt,
    #[error("client storage unavailable")]
    Storage(#[from] rusqlite::Error),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalProjectId(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanonicalWorkspaceId(String);

#[derive(Clone, Debug, Eq, PartialEq)]
struct RecentRootDisplayName(String);

impl CanonicalProjectId {
    fn parse(value: &str) -> Result<Self, RecentRootError> {
        canonical_uuid_v7(value)
            .then(|| Self(value.to_owned()))
            .ok_or(RecentRootError::Invalid)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl CanonicalWorkspaceId {
    fn parse(value: &str) -> Result<Self, RecentRootError> {
        canonical_uuid_v7(value)
            .then(|| Self(value.to_owned()))
            .ok_or(RecentRootError::Invalid)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl RecentRootDisplayName {
    fn parse(value: &str) -> Result<Self, RecentRootError> {
        valid_display_name(value)
            .then(|| Self(value.to_owned()))
            .ok_or(RecentRootError::Invalid)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl LocalStore {
    /// Records a root that has already been bound to canonical runtime identity.
    ///
    /// Native root metadata remains private to this store and is never returned.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid identity, display data, or storage failure.
    pub fn record_recent_root(
        &mut self,
        project_id: &str,
        workspace_id: &str,
        display_name: &str,
        last_opened_at: i64,
        native_root_metadata: &str,
    ) -> Result<RecentRoot, RecentRootError> {
        let root = recent_root(project_id, workspace_id, display_name, last_opened_at)?;
        if !valid_native_metadata(native_root_metadata) {
            return Err(RecentRootError::Invalid);
        }
        let transaction = self.connection.transaction()?;
        let current: Option<String> = transaction
            .query_row(
                "SELECT project_id FROM recent_roots WHERE workspace_id = ?1",
                [root.workspace_id.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if current.is_some_and(|project_id| project_id != root.project_id.as_str()) {
            return Err(RecentRootError::Invalid);
        }
        transaction.execute(
            "
            INSERT INTO recent_roots (
                project_id, workspace_id, display_name, last_opened_at,
                root_state, native_root_metadata, legacy_project_id
            ) VALUES (?1, ?2, ?3, ?4, 'ready', ?5, NULL)
            ON CONFLICT(workspace_id) DO UPDATE SET
                project_id = excluded.project_id,
                display_name = excluded.display_name,
                last_opened_at = excluded.last_opened_at,
                root_state = excluded.root_state,
                native_root_metadata = excluded.native_root_metadata,
                legacy_project_id = NULL
            ",
            params![
                root.project_id.as_str(),
                root.workspace_id.as_str(),
                root.display_name.as_str(),
                root.last_opened_at,
                native_root_metadata,
            ],
        )?;
        transaction.commit()?;
        Ok(root)
    }

    /// Lists only roots that have canonical Project and Workspace identity.
    ///
    /// # Errors
    ///
    /// Returns a closed error when a stored row cannot be decoded safely.
    pub fn list_recent_roots(&self) -> Result<Vec<RecentRoot>, RecentRootError> {
        let mut statement = self.connection.prepare(
            "
            SELECT project_id, workspace_id, display_name, last_opened_at
            FROM recent_roots
            WHERE root_state = 'ready'
            ORDER BY last_opened_at DESC, workspace_id DESC
            ",
        )?;
        let rows = statement.query_map([], decode_recent_root)?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| RecentRootError::Corrupt)
    }

    /// Looks up a canonical recent root by Project ID without returning native metadata.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an invalid ID or corrupt storage row.
    pub fn get_recent_root(&self, project_id: &str) -> Result<Option<RecentRoot>, RecentRootError> {
        let project_id = CanonicalProjectId::parse(project_id)?;
        self.connection
            .query_row(
                "
                SELECT project_id, workspace_id, display_name, last_opened_at
                FROM recent_roots
                WHERE root_state = 'ready' AND project_id = ?1
                ORDER BY last_opened_at DESC, workspace_id DESC
                LIMIT 1
                ",
                [project_id.as_str()],
                decode_recent_root,
            )
            .optional()
            .map_err(RecentRootError::from)
    }

    /// Lists every recent Workspace belonging to one canonical Project.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid ID or corrupt storage data.
    pub fn list_project_roots(&self, project_id: &str) -> Result<Vec<RecentRoot>, RecentRootError> {
        let project_id = CanonicalProjectId::parse(project_id)?;
        let mut statement = self.connection.prepare(
            "SELECT project_id, workspace_id, display_name, last_opened_at FROM recent_roots WHERE root_state = 'ready' AND project_id = ?1 ORDER BY last_opened_at DESC, workspace_id DESC",
        )?;
        statement
            .query_map([project_id.as_str()], decode_recent_root)?
            .collect::<Result<_, _>>()
            .map_err(|_| RecentRootError::Corrupt)
    }

    /// Looks up exactly one canonical Workspace root.
    ///
    /// # Errors
    ///
    /// Returns a closed error for invalid ID or corrupt storage data.
    pub fn get_workspace_root(
        &self,
        workspace_id: &str,
    ) -> Result<Option<RecentRoot>, RecentRootError> {
        let workspace_id = CanonicalWorkspaceId::parse(workspace_id)?;
        self.connection
            .query_row(
                "SELECT project_id, workspace_id, display_name, last_opened_at FROM recent_roots WHERE root_state = 'ready' AND workspace_id = ?1",
                [workspace_id.as_str()],
                decode_recent_root,
            )
            .optional()
            .map_err(RecentRootError::from)
    }
}

fn decode_recent_root(row: &rusqlite::Row<'_>) -> rusqlite::Result<RecentRoot> {
    let project_id: String = row.get(0)?;
    let workspace_id: String = row.get(1)?;
    let display_name: String = row.get(2)?;
    let last_opened_at: i64 = row.get(3)?;
    recent_root(&project_id, &workspace_id, &display_name, last_opened_at)
        .map_err(|_| rusqlite::Error::InvalidQuery)
}

fn recent_root(
    project_id: &str,
    workspace_id: &str,
    display_name: &str,
    last_opened_at: i64,
) -> Result<RecentRoot, RecentRootError> {
    if !(0..=MAX_SAFE_TIMESTAMP).contains(&last_opened_at) {
        return Err(RecentRootError::Invalid);
    }
    Ok(RecentRoot {
        project_id: CanonicalProjectId::parse(project_id)?,
        workspace_id: CanonicalWorkspaceId::parse(workspace_id)?,
        display_name: RecentRootDisplayName::parse(display_name)?,
        last_opened_at,
    })
}

pub fn valid_display_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DISPLAY_NAME_BYTES
        && !value.chars().any(|character| {
            character.is_control()
                || matches!(character, '\u{00AD}' | '\u{0600}'..='\u{0605}' | '\u{061C}' | '\u{06DD}' | '\u{070F}' | '\u{0890}'..='\u{0891}' | '\u{08E2}' | '\u{180E}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2064}' | '\u{2066}'..='\u{206F}' | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{110BD}' | '\u{110CD}' | '\u{13430}'..='\u{1343F}' | '\u{1BCA0}'..='\u{1BCA3}' | '\u{1D173}'..='\u{1D17A}' | '\u{E0001}' | '\u{E0020}'..='\u{E007F}')
        })
}

pub fn valid_native_metadata(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_NATIVE_ROOT_METADATA_BYTES && !value.contains('\0')
}

fn canonical_uuid_v7(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes[14] == b'7'
        && matches!(bytes[19], b'8'..=b'9' | b'a'..=b'b')
        && bytes.iter().enumerate().all(|(index, byte)| {
            [8, 13, 18, 23].contains(&index) || matches!(byte, b'0'..=b'9' | b'a'..=b'f')
        })
}
