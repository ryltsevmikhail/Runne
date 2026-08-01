impl<S, V, D, C> MigrationRouter<S, V, D, C>
where
    S: MigrationControlStore + MigrationRoutingStore,
    V: FenceValidationPort,
    D: MigrationDispatchPort,
    C: Clock + Send + Sync,
{
    /// Construct a router from its durable and protected-boundary authorities.
    pub fn new(
        store: Arc<S>,
        features: Arc<VerifiedFeatureRegistry>,
        fence: MigrationFenceGuard<V>,
        dispatch: Arc<D>,
        clock: Arc<C>,
    ) -> Self {
        Self::new_with_fallback_policy(
            store,
            features,
            fence,
            dispatch,
            clock,
            PreDispatchFallbackPolicy::Disabled,
        )
    }

    /// Construct a router with an explicit pre-dispatch fallback policy.
    pub fn new_with_fallback_policy(
        store: Arc<S>,
        features: Arc<VerifiedFeatureRegistry>,
        fence: MigrationFenceGuard<V>,
        dispatch: Arc<D>,
        clock: Arc<C>,
        fallback_policy: PreDispatchFallbackPolicy,
    ) -> Self {
        Self::new_with_routing_policies(
            store,
            features,
            fence,
            dispatch,
            clock,
            fallback_policy,
            LegacyAdmissionPolicy::Open,
        )
    }

    /// Construct a router with exact fallback and legacy-admission policies.
    pub fn new_with_routing_policies(
        store: Arc<S>,
        features: Arc<VerifiedFeatureRegistry>,
        fence: MigrationFenceGuard<V>,
        dispatch: Arc<D>,
        clock: Arc<C>,
        fallback_policy: PreDispatchFallbackPolicy,
        legacy_admission_policy: LegacyAdmissionPolicy,
    ) -> Self {
        Self {
            store,
            features,
            fence,
            dispatch,
            clock,
            fallback_policy,
            legacy_admission_policy,
            aggregate_locks: Mutex::new(HashMap::new()),
        }
    }
}
