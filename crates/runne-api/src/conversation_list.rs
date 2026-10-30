/// Durable conversation summary; includes sessions with no task or message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationListItem {
    /// Conversation identity.
    pub conversation_id: ConversationId,
    /// Exact owning workspace.
    pub workspace_id: WorkspaceId,
    /// Committed stream version.
    pub stream_version: u64,
    /// First user message, bounded to 80 Unicode scalar values, or default title.
    pub title: String,
    /// Most recent committed event time.
    pub updated_at: NonNegativeUnixMillis,
}

/// Ordered bounded page scoped to the authenticated principal and workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConversationListPage {
    /// Ascending conversation UUID order, at most the requested 100 items.
    pub items: Vec<ConversationListItem>,
    /// Exclusive continuation identity in this same principal/workspace scope.
    pub next_after: Option<ConversationId>,
}
