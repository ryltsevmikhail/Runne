use crate::taskrun_auto_worker::{AutomaticTaskRunService, run_automatic_taskrun_worker};

impl<E, U, I> WorkerRegistry<E, U, I>
where
    E: EventStore + Send + Sync + 'static,
    U: UnitOfWork + Send + Sync + 'static,
    I: IdGenerator + Send + Sync + 'static,
{
    fn start_automatic_taskrun_worker(
        &mut self,
        service: Option<Arc<dyn AutomaticTaskRunService>>,
    ) {
        let Some(service) = service else { return };
        let stop = self.automatic_taskrun_stop.clone();
        self.join_set.spawn(async move {
            run_automatic_taskrun_worker(service, stop).await;
            RuntimeTaskExit::AutomaticTaskRunQueue
        });
    }

    fn stop_automatic_taskrun_worker(&self) {
        self.automatic_taskrun_stop.cancel();
    }
}
