impl SecureLocalHttpHost {
    /// Mounts the Local Engine status surface (Plan Task 14). The data
    /// source is injected; composition keeps full ownership of what it
    /// exposes.
    #[allow(dead_code)] // Mounted by the daemon once its data source is composed.
    pub(crate) fn with_local_engine_state(
        mut self,
        state: crate::local_engine::LocalEngineState,
    ) -> Self {
        self.router = self
            .router
            .merge(crate::local_engine::local_engine_router(state));
        self
    }
}
