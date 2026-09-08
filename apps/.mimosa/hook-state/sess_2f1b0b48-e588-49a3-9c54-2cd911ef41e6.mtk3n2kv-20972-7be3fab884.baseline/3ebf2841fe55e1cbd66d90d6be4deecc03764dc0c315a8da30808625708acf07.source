impl TaskRunSubscriptionManager {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers one bounded renderer subscription.
    ///
    /// # Errors
    ///
    /// Returns a closed error when identity, window ownership, capacity, or
    /// registry state is invalid.
    pub fn subscribe<S>(
        &self,
        source: Arc<S>,
        task_run_id: &str,
        window_label: &str,
        channel: Channel<TaskRunChannelEvent>,
    ) -> Result<String, TaskRunChannelError>
    where
        S: TaskRunUpdateSource,
    {
        if !is_canonical_id(task_run_id) || window_label.is_empty() {
            return Err(TaskRunChannelError::unavailable());
        }
        let id = Uuid::now_v7().to_string();
        let control = Arc::new(SubscriptionControl::new());
        let (start_tx, start_rx) = tokio::sync::oneshot::channel();
        let task = spawn_subscription(
            Arc::downgrade(&self.registry), id.clone(), source, task_run_id.to_owned(),
            Arc::clone(&control), channel, start_rx,
        );
        let mut registry = self.registry.lock().map_err(|_| TaskRunChannelError::unavailable())?;
        if registry.shutting_down
            || registry.subscriptions.len() >= MAX_ACTIVE_SUBSCRIPTIONS
            || registry.subscriptions.values().any(|value| value.window_label == window_label && value.task_run_id == task_run_id)
        {
            task.abort();
            return Err(TaskRunChannelError::unavailable());
        }
        registry.subscriptions.insert(id.clone(), SubscriptionRecord {
            window_label: window_label.to_owned(), task_run_id: task_run_id.to_owned(), control, task: Some(task),
        });
        drop(registry);
        let _ = start_tx.send(());
        Ok(id)
    }

    /// Acknowledges exactly the in-flight projection for one window.
    ///
    /// # Errors
    ///
    /// Returns a closed error for an unknown subscription, wrong window, or
    /// regressing acknowledgement.
    pub fn ack(&self, window_label: &str, subscription_id: &str, projection_revision: u64) -> Result<(), TaskRunChannelError> {
        let control = {
            let registry = self.registry.lock().map_err(|_| TaskRunChannelError::unavailable())?;
            let record = registry.subscriptions.get(subscription_id).ok_or_else(TaskRunChannelError::unavailable)?;
            if record.window_label != window_label { return Err(TaskRunChannelError::unavailable()); }
            let control = Arc::clone(&record.control);
            drop(registry);
            control
        };
        control.acknowledge(projection_revision).then_some(()).ok_or_else(TaskRunChannelError::unavailable)
    }

    /// Cancels and joins one owned renderer subscription.
    ///
    /// # Errors
    ///
    /// Returns a closed error when the subscription is unknown, belongs to a
    /// different window, or its worker cannot be joined.
    pub async fn cancel(&self, window_label: &str, subscription_id: &str) -> Result<(), TaskRunChannelError> {
        let (control, task) = {
            let mut registry = self.registry.lock().map_err(|_| TaskRunChannelError::unavailable())?;
            let record = registry.subscriptions.get_mut(subscription_id).ok_or_else(TaskRunChannelError::unavailable)?;
            if record.window_label != window_label { return Err(TaskRunChannelError::unavailable()); }
            let result = (Arc::clone(&record.control), record.task.take().ok_or_else(TaskRunChannelError::unavailable)?);
            drop(registry);
            result
        };
        control.cancel();
        task.await.map_err(|_| TaskRunChannelError::unavailable())?;
        if let Ok(mut registry) = self.registry.lock()
            && registry.subscriptions.get(subscription_id).is_some_and(|record| record.window_label == window_label && record.task.is_none())
        {
            let _ = registry.subscriptions.remove(subscription_id);
        }
        Ok(())
    }

    pub fn cancel_window(&self, window_label: &str) {
        let ids = self.registry.lock().map_or_else(|_| Vec::new(), |registry| registry.subscriptions.iter().filter(|(_, record)| record.window_label == window_label).map(|(id, _)| id.clone()).collect());
        for id in ids {
            let manager = self.clone();
            let label = window_label.to_owned();
            tokio::spawn(async move { let _ = manager.cancel(&label, &id).await; });
        }
    }

    pub fn shutdown(&self) {
        let controls = self.registry.lock().map_or_else(|_| Vec::new(), |mut registry| {
            registry.shutting_down = true;
            registry.subscriptions.values().map(|record| Arc::clone(&record.control)).collect::<Vec<_>>()
        });
        for control in controls { control.cancel(); }
    }
}

fn is_canonical_id(value: &str) -> bool {
    CanonicalId::parse(value).is_ok()
}
