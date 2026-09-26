impl ConversationSubscriptionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(ManagerInner {
                registry: Mutex::new(Registry::default()),
            }),
        }
    }

    /// Admits and starts one bounded native Conversation subscription.
    ///
    /// # Errors
    ///
    /// Returns only a closed error when the project, manager or quota is
    /// unavailable.
    pub fn subscribe<S>(
        &self,
        source: Arc<S>,
        project_id: i64,
        window_label: &str,
        on_update: Channel<ConversationChannelEvent>,
    ) -> Result<String, ConversationChannelError>
    where
        S: ConversationUpdateSource,
    {
        if project_id <= 0 || window_label.is_empty() {
            return Err(ConversationChannelError::unavailable());
        }
        self.subscribe_target(
            source,
            ConversationSubscriptionTarget::Project(project_id),
            format!("project:{project_id}"),
            window_label,
            on_update,
        )
    }

    /// Admits and starts one bounded subscription for an opaque `WorkspaceID`.
    ///
    /// # Errors
    ///
    /// Returns a closed error for malformed identity, duplicate ownership, or
    /// unavailable subscription capacity.
    pub fn subscribe_workspace<S>(
        &self,
        source: Arc<S>,
        workspace_id: &str,
        window_label: &str,
        on_update: Channel<ConversationChannelEvent>,
    ) -> Result<String, ConversationChannelError>
    where
        S: ConversationUpdateSource,
    {
        let workspace_id = CanonicalId::parse(workspace_id)
            .map_err(|_| ConversationChannelError::unavailable())?
            .to_string();
        if window_label.is_empty() {
            return Err(ConversationChannelError::unavailable());
        }
        self.subscribe_target(
            source,
            ConversationSubscriptionTarget::Workspace(workspace_id.clone()),
            format!("workspace:{workspace_id}"),
            window_label,
            on_update,
        )
    }

    /// Admits the singleton TextOnly conversation subscription.
    pub fn subscribe_text_only<S>(
        &self,
        source: Arc<S>,
        window_label: &str,
        on_update: Channel<ConversationChannelEvent>,
    ) -> Result<String, ConversationChannelError>
    where
        S: ConversationUpdateSource,
    {
        if window_label.is_empty() {
            return Err(ConversationChannelError::unavailable());
        }
        self.subscribe_target(
            source,
            ConversationSubscriptionTarget::TextOnly,
            "text-only:v1".to_owned(),
            window_label,
            on_update,
        )
    }

    fn subscribe_target<S>(
        &self,
        source: Arc<S>,
        target: ConversationSubscriptionTarget,
        conversation_key: String,
        window_label: &str,
        on_update: Channel<ConversationChannelEvent>,
    ) -> Result<String, ConversationChannelError>
    where
        S: ConversationUpdateSource,
    {
        let pair = (window_label.to_owned(), conversation_key.clone());
        let (subscription_id, control) = {
            let mut registry = self
                .inner
                .registry
                .lock()
                .map_err(|_| ConversationChannelError::unavailable())?;
            if registry.shutting_down {
                return Err(ConversationChannelError::unavailable());
            }
            if registry.by_pair.contains_key(&pair) {
                return Err(ConversationChannelError::unavailable());
            }
            if registry.subscriptions.len() >= MAX_ACTIVE_SUBSCRIPTIONS {
                return Err(ConversationChannelError::unavailable());
            }
            let subscription_id = Uuid::now_v7().to_string();
            let control = Arc::new(SubscriptionControl::new());
            registry.by_pair.insert(pair, subscription_id.clone());
            registry.subscriptions.insert(
                subscription_id.clone(),
                SubscriptionRecord {
                    window_label: window_label.to_owned(),
                    conversation_key,
                    control: Arc::clone(&control),
                },
            );
            drop(registry);
            (subscription_id, control)
        };
        spawn_subscription(
            Arc::downgrade(&self.inner),
            subscription_id.clone(),
            source,
            target,
            control,
            on_update,
        );
        Ok(subscription_id)
    }

    /// Acknowledges exactly the update currently in flight for the caller.
    ///
    /// # Errors
    ///
    /// Unknown, cross-window, stale, regressing or future acknowledgements
    /// cancel the identified subscription and return a closed error.
    pub fn ack(
        &self,
        window_label: &str,
        subscription_id: &str,
        projection_revision: u64,
    ) -> Result<(), ConversationChannelError> {
        let control = {
            let registry = self
                .inner
                .registry
                .lock()
                .map_err(|_| ConversationChannelError::unavailable())?;
            let record = registry
                .subscriptions
                .get(subscription_id)
                .ok_or_else(ConversationChannelError::unavailable)?;
            if record.window_label != window_label {
                return Err(ConversationChannelError::unavailable());
            }
            let control = Arc::clone(&record.control);
            drop(registry);
            control
        };
        if control.acknowledge(projection_revision) {
            return Ok(());
        }
        Err(ConversationChannelError::unavailable())
    }

    /// Cancels exactly one caller-owned subscription.
    ///
    /// # Errors
    ///
    /// Returns a closed error when that subscription does not exist or belongs
    /// to another window.
    pub fn cancel(
        &self,
        window_label: &str,
        subscription_id: &str,
    ) -> Result<(), ConversationChannelError> {
        let control = {
            let mut registry = self
                .inner
                .registry
                .lock()
                .map_err(|_| ConversationChannelError::unavailable())?;
            let record = registry
                .subscriptions
                .get(subscription_id)
                .ok_or_else(ConversationChannelError::unavailable)?;
            if record.window_label != window_label {
                return Err(ConversationChannelError::unavailable());
            }
            let control = remove_subscription(&mut registry, subscription_id)
                .ok_or_else(ConversationChannelError::unavailable)?;
            drop(registry);
            control
        };
        control.cancel();
        Ok(())
    }

    pub fn cancel_window(&self, window_label: &str) {
        let controls = {
            let Ok(registry) = self.inner.registry.lock() else {
                return;
            };
            registry
                .subscriptions
                .values()
                .filter(|record| record.window_label == window_label)
                .map(|record| Arc::clone(&record.control))
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
    }

    pub fn shutdown(&self) {
        let controls = {
            let Ok(mut registry) = self.inner.registry.lock() else {
                return;
            };
            registry.shutting_down = true;
            registry
                .subscriptions
                .values()
                .map(|record| Arc::clone(&record.control))
                .collect::<Vec<_>>()
        };
        for control in controls {
            control.cancel();
        }
    }
}
