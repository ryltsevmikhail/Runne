use runne_domain::id::{
    AttemptId, BudgetReservationId, CheckpointId, ContextManifestId, CycleId, EffectId,
    PlanEvaluationId, PlanId, ResultId, StepId, TaskRunId, WakeEvidenceId,
};

pub(super) trait IdBytes {
    fn id_bytes(&self) -> [u8; 16];
}
impl<T: IdBytes + ?Sized> IdBytes for &T {
    fn id_bytes(&self) -> [u8; 16] {
        (*self).id_bytes()
    }
}
macro_rules! ids { ($($value:ty),+ $(,)?) => { $(impl IdBytes for $value { fn id_bytes(&self) -> [u8; 16] { *self.as_bytes() } })+ }; }
ids!(
    AttemptId,
    BudgetReservationId,
    CheckpointId,
    ContextManifestId,
    CycleId,
    EffectId,
    PlanEvaluationId,
    PlanId,
    ResultId,
    StepId,
    TaskRunId,
    WakeEvidenceId
);
pub(super) fn id(value: impl IdBytes) -> [u8; 16] {
    value.id_bytes()
}
pub(super) fn digest(value: runne_domain::id::IntegrityDigest) -> [u8; 32] {
    *value.as_bytes()
}
