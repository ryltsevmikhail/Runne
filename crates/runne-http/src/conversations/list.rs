#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConversationListQuery {
    workspace_id: String,
    limit: u16,
    after: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationListWire {
    items: Vec<ConversationListItemWire>,
    next_after: Option<String>,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConversationListItemWire {
    conversation_id: String,
    workspace_id: String,
    stream_version: u64,
    title: String,
    updated_at: i64,
}

async fn list_conversations<H>(
    State(state): State<ConversationHttpState<H>>,
    Extension(principal): Extension<AuthenticatedPrincipal>,
    Extension(request_id): Extension<RequestId>,
    query: Result<
        axum::extract::Query<ConversationListQuery>,
        axum::extract::rejection::QueryRejection,
    >,
) -> Response
where
    H: ConversationCommandHostPort + ConversationQueryHostPort,
{
    let Ok(axum::extract::Query(query)) = query else {
        return bad_request("invalid_request", &request_id);
    };
    if !(1..=100).contains(&query.limit) {
        return bad_request("invalid_limit", &request_id);
    }
    let Ok(workspace) = query.workspace_id.parse() else {
        return bad_request("invalid_workspace_id", &request_id);
    };
    let after = match query.after.map(|id| id.parse()).transpose() {
        Ok(value) => value,
        Err(_) => return bad_request("invalid_cursor", &request_id),
    };
    match state
        .host
        .list_conversations(
            principal.as_api_principal().clone(),
            workspace,
            query.limit,
            after,
        )
        .await
    {
        Ok(page) => (
            StatusCode::OK,
            Json(ConversationListWire {
                items: page
                    .items
                    .into_iter()
                    .map(|item| ConversationListItemWire {
                        conversation_id: item.conversation_id.to_string(),
                        workspace_id: item.workspace_id.to_string(),
                        stream_version: item.stream_version,
                        title: item.title,
                        updated_at: item.updated_at.as_i64(),
                    })
                    .collect(),
                next_after: page.next_after.map(|id| id.to_string()),
            }),
        )
            .into_response(),
        Err(error) => host_error_response(error, &request_id),
    }
}
