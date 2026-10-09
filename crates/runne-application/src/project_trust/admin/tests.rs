use std::cell::Cell;

use runne_api::{ApiPrincipalId, DaemonInstanceId, RuntimeSessionBinding, StableRuntimeBinding};
use runne_domain::{event::Sensitivity, id::EventLogLineageId};

use super::{
    AdminError, PolicyAdminAuthoritySource, PolicyAdminAuthorityVerifier,
    PolicyAdminBootstrapEvidence, PolicyAdminBootstrapVerifier, PolicyAdminSessionBinding,
    with_verified_policy_admin,
};

#[derive(Clone, Copy)]
enum Calls {
    None,
    Once,
    Twice,
}

struct Bootstrap;
impl PolicyAdminBootstrapVerifier for Bootstrap {
    fn verify_retained_protected_bootstrap(
        &self,
        _: &PolicyAdminBootstrapEvidence,
    ) -> Result<(), AdminError> {
        Ok(())
    }
}

struct Source {
    evidence: PolicyAdminBootstrapEvidence,
    calls: Calls,
}
impl PolicyAdminAuthoritySource for Source {
    fn with_current_evidence(
        &self,
        expected: &PolicyAdminSessionBinding,
        callback: &mut dyn FnMut(&PolicyAdminBootstrapEvidence) -> Result<(), AdminError>,
    ) -> Result<(), AdminError> {
        if self.evidence.binding() != expected {
            return Err(AdminError::AuthorityUnavailable);
        }
        match self.calls {
            Calls::None => Ok(()),
            Calls::Once => callback(&self.evidence),
            Calls::Twice => {
                callback(&self.evidence)?;
                callback(&self.evidence)
            }
        }
    }
}

fn binding(principal: &str, generation: u64) -> PolicyAdminSessionBinding {
    binding_with_lineage(
        principal,
        generation,
        "018f2e3a-7000-7000-8000-000000000003",
    )
}

fn binding_with_lineage(
    principal: &str,
    generation: u64,
    lineage: &str,
) -> PolicyAdminSessionBinding {
    let runtime = RuntimeSessionBinding::new(
        StableRuntimeBinding::new(
            [1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 1],
            ApiPrincipalId::new(principal).unwrap(),
            lineage.parse::<EventLogLineageId>().unwrap(),
            "client/2",
            [3; 32],
            [4; 32],
        )
        .unwrap(),
        DaemonInstanceId::from_bytes([1, 143, 46, 58, 112, 0, 112, 0, 128, 0, 0, 0, 0, 0, 0, 2]),
        generation,
        [generation as u8; 16],
        generation,
        Sensitivity::Internal,
        [6; 32],
    )
    .unwrap();
    PolicyAdminSessionBinding::new(runtime, [7; 16], [8; 32], generation, deadline())
}

fn evidence(binding: PolicyAdminSessionBinding) -> PolicyAdminBootstrapEvidence {
    PolicyAdminBootstrapEvidence::new(binding, [9; 32], [10; 32])
}

fn deadline() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 60_000
}

#[test]
fn zero_callback_rejects_and_wrong_full_binding_never_runs_action() {
    let expected = binding("owner", 1);
    let verifier_port = Bootstrap;
    let source = Source {
        evidence: evidence(expected.clone()),
        calls: Calls::None,
    };
    let verifier = PolicyAdminAuthorityVerifier::new(&verifier_port, &source);
    let action_count = Cell::new(0);
    assert_eq!(
        with_verified_policy_admin(&verifier, &expected, |_| {
            action_count.set(action_count.get() + 1);
            Ok(())
        }),
        Err(AdminError::CallbackContract)
    );
    assert_eq!(action_count.get(), 0);

    let source = Source {
        evidence: evidence(binding("different-owner", 1)),
        calls: Calls::Once,
    };
    let verifier = PolicyAdminAuthorityVerifier::new(&verifier_port, &source);
    assert_eq!(
        with_verified_policy_admin(&verifier, &expected, |_| {
            action_count.set(action_count.get() + 1);
            Ok(())
        }),
        Err(AdminError::AuthorityUnavailable)
    );
    assert_eq!(action_count.get(), 0);

    for wrong in [
        binding_with_lineage("owner", 1, "018f2e3a-7000-7000-8000-000000000013"),
        binding("owner", 2),
    ] {
        let source = Source {
            evidence: evidence(wrong),
            calls: Calls::Once,
        };
        let verifier = PolicyAdminAuthorityVerifier::new(&verifier_port, &source);
        assert_eq!(
            with_verified_policy_admin(&verifier, &expected, |_| {
                action_count.set(action_count.get() + 1);
                Ok(())
            }),
            Err(AdminError::AuthorityUnavailable)
        );
        assert_eq!(action_count.get(), 0);
    }
}

#[test]
fn second_callback_never_reexecutes_action_and_requires_reconciliation() {
    let expected = binding("owner", 1);
    let verifier_port = Bootstrap;
    let source = Source {
        evidence: evidence(expected.clone()),
        calls: Calls::Twice,
    };
    let verifier = PolicyAdminAuthorityVerifier::new(&verifier_port, &source);
    let action_count = Cell::new(0);
    assert_eq!(
        with_verified_policy_admin(&verifier, &expected, |_| {
            action_count.set(action_count.get() + 1);
            Ok(())
        }),
        Err(AdminError::UnknownAfterAction)
    );
    assert_eq!(action_count.get(), 1);
}
