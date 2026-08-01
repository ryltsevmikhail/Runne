impl<S, H> MigrationService<S, H>
where
    S: MigrationControlStore,
    H: ShadowExecutionPort,
{
    /// Construct the service from abstract persistence and shadow ports.
    pub fn new(store: S, shadow: H) -> Self {
        Self {
            store,
            _shadow: shadow,
        }
    }

    /// Load one durable migration plan.
    pub fn load_plan(
        &self,
        plan_id: &MigrationPlanId,
    ) -> Result<Option<LoadedMigrationPlan>, MigrationError> {
        self.store.load_plan(plan_id).map_err(map_store_error)
    }

    /// Load the current routing head for an exact routing unit.
    pub fn routing_head(
        &self,
        unit: &super::types::RoutingUnit,
    ) -> Result<Option<RoutingSnapshot>, MigrationError> {
        self.store.load_routing_head(unit).map_err(map_store_error)
    }


}
