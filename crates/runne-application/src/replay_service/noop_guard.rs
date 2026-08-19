struct NoopDeliveryGuard;

impl ReplayDeliveryPrecommitGuard for NoopDeliveryGuard {
    fn inspect(
        &self,
        _session: &ReplaySession,
        _events: &[ReplayEvent],
    ) -> Result<(), ReplayError> {
        Ok(())
    }
}
