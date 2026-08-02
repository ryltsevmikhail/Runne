use crate::verification::digest::VerificationDigest;
use crate::verification::identity::*;
use crate::verification::intent::{ConsumptionIntent, DispatchEvidence, IntentState};
use std::collections::{BTreeMap, HashMap};

include!("evaluation/core.rs");

#[cfg(test)]
mod tests {
    include!("evaluation/tests.rs");
}

include!("evaluation/evaluator.rs");
include!("evaluation/intent.rs");

#[cfg(test)]
mod intent_tests {
    include!("evaluation/intent_tests.rs");
}
