pub(super) struct ResumeResponseDeniedGuard;

impl ProhibitedContentPort for ResumeResponseDeniedGuard {
    fn inspect(
        &self,
        _: CanonicalContentBoundary,
        bytes: &[u8],
    ) -> Result<ContentDisposition, ContentGuardError> {
        if bytes
            .windows(b"acceptedPromotion".len())
            .any(|window| window == b"acceptedPromotion")
        {
            Ok(ContentDisposition::Prohibited { policy_epoch: 3 })
        } else {
            Ok(ContentDisposition::Allowed { policy_epoch: 3 })
        }
    }
}

impl RetentionGapFixture {
    pub(super) fn v2_app(&self) -> axum::Router {
        self.v2_app_with_guard(Arc::new(AvailableGuard))
    }

    pub(super) fn v2_app_with_guard(
        &self,
        guard: Arc<dyn ProhibitedContentPort>,
    ) -> axum::Router {
        replay_app_with_v2(&self.path, binding(), guard, true)
    }

    pub(super) fn database_path(&self) -> &std::path::Path {
        &self.path
    }

    pub(super) async fn open_authenticated(&self) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(open_request(
                self.taskrun_id,
                Some(SESSION_AUTHORITY),
                Some(&self.from_cursor),
            ))
            .await
            .unwrap()
    }

    pub(super) async fn open_unauthenticated(&self) -> axum::response::Response {
        self.app
            .clone()
            .oneshot(open_request(self.taskrun_id, None, Some(&self.from_cursor)))
            .await
            .unwrap()
    }

    pub(super) fn subscriptions(&self) -> i64 {
        rusqlite::Connection::open(&self.path)
            .unwrap()
            .query_row("SELECT COUNT(*) FROM _replay_subscriptions", [], |row| {
                row.get(0)
            })
            .unwrap()
    }
}
