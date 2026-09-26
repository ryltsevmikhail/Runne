#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn open_workspace_conversation(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
) -> Result<runne_app_core::ConversationSnapshot, IpcError> {
    state
        .open_workspace_conversation(&workspace_id)
        .await
        .map_err(|_| IpcError { code: "conversation_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn resync_workspace_conversation(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
) -> Result<runne_app_core::ConversationSnapshot, IpcError> {
    state
        .resync_workspace_conversation(&workspace_id)
        .await
        .map_err(|_| IpcError { code: "conversation_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
async fn send_workspace_message(
    state: State<'_, Arc<AppCore>>,
    workspace_id: String,
    text: String,
) -> Result<runne_app_core::ConversationSnapshot, IpcError> {
    if text.is_empty() || text.len() > 64 * 1024 {
        return Err(IpcError { code: "conversation_message_rejected" });
    }
    state
        .send_workspace_message(&workspace_id, &text)
        .await
        .map_err(|_| IpcError { code: "conversation_unavailable" })
}

#[tauri::command]
async fn open_text_only_conversation(
    state: State<'_, Arc<AppCore>>,
) -> Result<runne_app_core::ConversationSnapshot, IpcError> {
    state.open_text_only_conversation().await.map_err(|_| IpcError { code: "conversation_unavailable" })
}

#[tauri::command]
async fn resync_text_only_conversation(
    state: State<'_, Arc<AppCore>>,
) -> Result<runne_app_core::ConversationSnapshot, IpcError> {
    state.resync_text_only_conversation().await.map_err(|_| IpcError { code: "conversation_unavailable" })
}

#[tauri::command]
async fn send_text_only_message(
    state: State<'_, Arc<AppCore>>,
    text: String,
) -> Result<runne_app_core::ConversationSnapshot, IpcError> {
    if text.is_empty() || text.len() > 64 * 1024 {
        return Err(IpcError { code: "conversation_message_rejected" });
    }
    state.send_text_only_message(&text).await.map_err(|_| IpcError { code: "conversation_unavailable" })
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn subscribe_text_only_conversation(
    window: WebviewWindow,
    state: State<'_, Arc<AppCore>>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    on_update: tauri::ipc::Channel<conversation_channel::ConversationChannelEvent>,
) -> Result<String, conversation_channel::ConversationChannelError> {
    subscriptions.subscribe_text_only(Arc::clone(&*state), window.label(), on_update)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn subscribe_workspace_conversation(
    window: WebviewWindow,
    state: State<'_, Arc<AppCore>>,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    workspace_id: String,
    on_update: tauri::ipc::Channel<conversation_channel::ConversationChannelEvent>,
) -> Result<String, conversation_channel::ConversationChannelError> {
    subscriptions.subscribe_workspace(Arc::clone(&*state), &workspace_id, window.label(), on_update)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn ack_conversation_update(
    window: WebviewWindow,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
    projection_revision: u64,
) -> Result<(), conversation_channel::ConversationChannelError> {
    subscriptions.ack(window.label(), &subscription_id, projection_revision)
}

#[tauri::command]
#[allow(clippy::needless_pass_by_value)]
fn cancel_conversation_subscription(
    window: WebviewWindow,
    subscriptions: State<'_, ConversationSubscriptionManager>,
    subscription_id: String,
) -> Result<(), conversation_channel::ConversationChannelError> {
    subscriptions.cancel(window.label(), &subscription_id)
}
