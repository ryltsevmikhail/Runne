use crate::protected_activation::linux_pair_diagnostics::record;

pub(super) fn stage_result<T, E>(stage: &'static str, result: Result<T, E>) -> Result<T, E> {
    record(stage, result.is_ok());
    result
}
