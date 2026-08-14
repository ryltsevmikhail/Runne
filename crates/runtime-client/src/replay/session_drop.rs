impl Drop for ReplayLiveSession {
    fn drop(&mut self) {
        let client = self.client.clone();
        let session_id = self.session_id.clone();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                client.close_replay_session(&session_id),
            )
            .await;
        });
    }
}
