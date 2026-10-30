/// Durable conversation summary, including an empty session.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationSummary {
    /// Stable conversation identity.
    pub conversation_id: CanonicalId,
    /// Exact owning workspace.
    pub workspace_id: CanonicalId,
    /// Last committed stream version.
    pub stream_version: u64,
    /// Bounded first-message title, or the empty-session title.
    pub title: String,
    /// Last committed event timestamp in milliseconds.
    pub updated_at: u64,
}

/// Deterministic page read under the authenticated principal and workspace.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConversationPage {
    /// At most 100 summaries in ascending conversation-ID order.
    pub items: Vec<ConversationSummary>,
    /// Exclusive continuation, reusable only with the same workspace query.
    pub next_after: Option<CanonicalId>,
}

impl AuthenticatedRuntimeClient {
    /// Lists durable conversations belonging to this principal and workspace.
    ///
    /// # Errors
    /// Rejects invalid limits, malformed or cross-workspace responses, and transport errors.
    pub async fn list_conversations(
        &self,
        workspace: CanonicalId,
        limit: u16,
        after: Option<CanonicalId>,
    ) -> Result<ConversationPage, RuntimeApiError> {
        if !(1..=100).contains(&limit) {
            return Err(invalid_request());
        }
        let mut request = self
            .http_client()
            .get(self.url("/v1/conversations"))
            .query(&[
                ("workspaceId", workspace.to_string()),
                ("limit", limit.to_string()),
            ]);
        if let Some(after) = after {
            request = request.query(&[("after", after.to_string())]);
        }
        let response = self
            .authenticated_request(request)?
            .send()
            .await
            .map_err(map_transport)?;
        let page: ConversationPage = read_success_json(response, &[200]).await?;
        validate_conversation_page(page, workspace, limit, after)
    }
}

fn validate_conversation_page(
    page: ConversationPage,
    workspace: CanonicalId,
    limit: u16,
    after: Option<CanonicalId>,
) -> Result<ConversationPage, RuntimeApiError> {
    if page.items.len() > usize::from(limit)
        || page.items.iter().any(|item| {
            item.workspace_id != workspace
                || item.stream_version == 0
                || item.title.chars().count() > 80
                || after.is_some_and(|id| item.conversation_id <= id)
        })
        || page
            .items
            .windows(2)
            .any(|pair| pair[0].conversation_id >= pair[1].conversation_id)
        || page.next_after.is_some_and(|id| {
            page.items.len() != usize::from(limit)
                || page
                    .items
                    .last()
                    .is_none_or(|item| item.conversation_id != id)
        })
    {
        return Err(invalid_response());
    }
    Ok(page)
}

#[cfg(test)]
mod conversation_list_tests {
    use super::*;
    #[test]
    fn conversation_page_rejects_cross_workspace_and_cursor_drift() {
        let workspace = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000001").unwrap();
        let id = CanonicalId::parse("018f2e3a-7000-7000-8000-000000000002").unwrap();
        let page = ConversationPage {
            items: vec![ConversationSummary {
                conversation_id: id,
                workspace_id: workspace,
                stream_version: 1,
                title: "New session".into(),
                updated_at: 1,
            }],
            next_after: Some(id),
        };
        assert!(validate_conversation_page(page.clone(), workspace, 1, None).is_ok());
        assert!(validate_conversation_page(page.clone(), id, 1, None).is_err());
        assert!(validate_conversation_page(page.clone(), workspace, 1, Some(id)).is_err());
        let mut bad = page;
        bad.next_after = Some(workspace);
        assert!(validate_conversation_page(bad, workspace, 1, None).is_err());
    }
}
