use super::*;

impl CanonicalProviderExecutionService for DaemonCanonicalProviderService {
    fn execute(
        &self,
        job: CanonicalProviderExecutionJob,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        self.execute_internal(job, None, None)
    }

    fn execute_claimed(
        &self,
        job: CanonicalProviderExecutionJob,
        assignment: runne_application::ports::TaskRunAssignmentIdentity,
    ) -> runne_provider::ProviderFuture<
        '_,
        Result<runne_application::ports::TextGenerationReceipt, CanonicalProviderExecutionError>,
    > {
        self.execute_internal(job, Some(assignment), None)
    }
}

mod execute;
mod failure;
mod route;
pub(in crate::canonical_provider) use route::SecondaryProfileRoute;
