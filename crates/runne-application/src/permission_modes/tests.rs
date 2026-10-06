use std::collections::BTreeSet;
use std::str::FromStr;

use runne_domain::id::{
    AttemptId, CommandId, IdempotencyKey, IntegrityDigest, InvocationId, TaskRunId, WorkspaceId,
};

use super::*;

struct MockAdmission;

impl NativeScopeAdmissionPort for MockAdmission {
    fn admit_mode_readiness(
        &self,
        _mode: PermissionMode,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        Ok(digest(98))
    }

    fn admit_scope(
        &self,
        _scope: &CompositeEffectScope,
    ) -> Result<IntegrityDigest, NativeAdmissionError> {
        Ok(digest(99))
    }
}

include!("tests_policy_cases.rs");
include!("tests_scope_cases.rs");
include!("tests_support.rs");
