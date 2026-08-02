impl<S, V, D, C> MigrationRouter<S, V, D, C>
where
    S: MigrationControlStore + MigrationRoutingStore,
    V: FenceValidationPort,
    D: MigrationDispatchPort,
    C: Clock + Send + Sync,
{
    fn aggregate_lock(
        &self,
        aggregate_id: &AggregateId,
    ) -> Result<Arc<AsyncMutex<()>>, MigrationRoutingError> {
        let mut locks = self
            .aggregate_locks
            .lock()
            .map_err(|_| MigrationRoutingError::Store(MigrationStoreError::Unavailable))?;
        if let Some(lock) = locks.get(aggregate_id).and_then(Weak::upgrade) {
            return Ok(lock);
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(aggregate_id.clone(), Arc::downgrade(&lock));
        Ok(lock)
    }

    fn release_aggregate_lock(
        &self,
        aggregate_id: &AggregateId,
        lock: &Arc<AsyncMutex<()>>,
    ) -> Result<(), MigrationRoutingError> {
        let mut locks = self
            .aggregate_locks
            .lock()
            .map_err(|_| MigrationRoutingError::Store(MigrationStoreError::Unavailable))?;
        if Arc::strong_count(lock) == 1
            && locks
                .get(aggregate_id)
                .and_then(Weak::upgrade)
                .is_some_and(|registered| Arc::ptr_eq(&registered, lock))
        {
            locks.remove(aggregate_id);
        }
        Ok(())
    }
}
