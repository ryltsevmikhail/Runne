fn fence_page_load<R: tauri::Runtime>(
    webview: &tauri::Webview<R>,
    payload: &tauri::webview::PageLoadPayload<'_>,
) {
    if matches!(payload.event(), tauri::webview::PageLoadEvent::Started) {
        let _ = webview
            .try_state::<DirectorySelectionManager>()
            .ok_or(())
            .and_then(|selections| {
                selections
                    .renderer_generations()
                    .page_loaded(webview.label())
                    .map_err(|_| ())
            });
        if let Some(intents) =
            webview.try_state::<crate::destructive_intent::DestructiveIntentManager>()
        {
            intents.invalidate_window(webview.label());
        }
        if let Some(intents) =
            webview.try_state::<crate::destructive_intent::ApprovalIntentManager>()
        {
            intents.invalidate_window(webview.label());
        }
        if let Some(intents) = webview
            .try_state::<crate::provider_credential_enrollment::CredentialIntentRegistry>()
        {
            intents.invalidate_window(webview.label());
        }
    }
}
