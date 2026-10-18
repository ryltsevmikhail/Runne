use std::{marker::PhantomData, rc::Rc};

use runne_api::RuntimeSessionBinding;
use thiserror::Error;

/// Errors shared by the unpublished managed-policy administrator ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AdminError {
    /// Current protected administrator authority could not be verified.
    #[error("managed policy administrator authority unavailable")]
    AuthorityUnavailable,
    /// A callback adapter violated its exactly-once contract.
    #[error("managed policy administrator callback contract failed")]
    CallbackContract,
    /// An operation may have committed before the trusted adapter failed.
    #[error("managed policy action outcome is unknown; retry the same command for readback")]
    UnknownAfterAction,
    /// The command or protected evidence does not match its exact binding.
    #[error("managed policy administrator binding was rejected")]
    Rejected,
    /// A different administrator or command already owns this singleton scope.
    #[error("managed policy administrator conflict")]
    Conflict,
    /// The existing project row or command moved since it was observed.
    #[error("managed policy command is stale")]
    Stale,
    /// The finite native consent ceremony expired.
    #[error("managed policy consent expired")]
    Expired,
    /// The command reached its cancelled terminal state.
    #[error("managed policy command was cancelled")]
    Cancelled,
    /// The command was invalidated by another policy or role change.
    #[error("managed policy command was invalidated")]
    Invalidated,
    /// The store or its retained identity is unavailable or corrupt.
    #[error("managed policy administrator store unavailable")]
    Unavailable,
}

/// Full current-session binding, including authenticated runtime and protected-launch data.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyAdminSessionBinding {
    runtime: RuntimeSessionBinding,
    protected_launch_id: [u8; 16],
    desktop_generation_key: [u8; 32],
    session_key_epoch: u64,
    session_expires_at_unix_ms: i64,
}

impl PolicyAdminSessionBinding {
    /// Creates an expected binding; authority still requires trusted retained-evidence verification.
    pub const fn new(
        runtime: RuntimeSessionBinding,
        protected_launch_id: [u8; 16],
        desktop_generation_key: [u8; 32],
        session_key_epoch: u64,
        session_expires_at_unix_ms: i64,
    ) -> Self {
        Self {
            runtime,
            protected_launch_id,
            desktop_generation_key,
            session_key_epoch,
            session_expires_at_unix_ms,
        }
    }

    /// Complete authenticated local runtime session supplied to the verifier.
    pub const fn runtime(&self) -> &RuntimeSessionBinding {
        &self.runtime
    }

    /// Protected launch identity checked by the trusted daemon verifier.
    pub const fn protected_launch_id(&self) -> &[u8; 16] {
        &self.protected_launch_id
    }

    /// Desktop generation key checked by the trusted daemon verifier.
    pub const fn desktop_generation_key(&self) -> &[u8; 32] {
        &self.desktop_generation_key
    }

    /// Epoch of the protected session key checked by the trusted daemon verifier.
    pub const fn session_key_epoch(&self) -> u64 {
        self.session_key_epoch
    }

    /// Expiry authenticated by the retained protected-session verifier.
    pub const fn session_expires_at_unix_ms(&self) -> i64 {
        self.session_expires_at_unix_ms
    }
}

/// Untrusted claims passed to a trusted retained-bootstrap verifier.
///
/// These bytes are claims only. Store authorization uses the private verified
/// types produced after the pinned daemon verifier accepts the retained evidence.
#[derive(Clone, PartialEq, Eq)]
pub struct PolicyAdminBootstrapEvidence {
    binding: PolicyAdminSessionBinding,
    installation_provenance: [u8; 32],
    retained_bootstrap_handle: [u8; 32],
}

impl PolicyAdminBootstrapEvidence {
    /// Wraps verifier input; construction does not authenticate these claims.
    pub const fn new(
        binding: PolicyAdminSessionBinding,
        installation_provenance: [u8; 32],
        retained_bootstrap_handle: [u8; 32],
    ) -> Self {
        Self {
            binding,
            installation_provenance,
            retained_bootstrap_handle,
        }
    }

    /// Session claims supplied for verification; this accessor does not authenticate them.
    pub const fn binding(&self) -> &PolicyAdminSessionBinding {
        &self.binding
    }

    /// Claimed installation provenance, accepted only after retained verification.
    pub const fn installation_provenance(&self) -> &[u8; 32] {
        &self.installation_provenance
    }

    /// Opaque retained handle for the trusted daemon verifier.
    pub const fn retained_bootstrap_handle(&self) -> &[u8; 32] {
        &self.retained_bootstrap_handle
    }
}

/// Private app proof that a trusted bootstrap verifier accepted retained evidence.
pub struct VerifiedPolicyAdminBootstrap {
    pub(crate) binding: PolicyAdminSessionBinding,
    pub(crate) installation_provenance: [u8; 32],
}

impl VerifiedPolicyAdminBootstrap {
    /// Full runtime and protected-launch binding accepted by the trusted verifier.
    pub const fn binding(&self) -> &PolicyAdminSessionBinding {
        &self.binding
    }

    /// Installation provenance accepted from retained protected evidence.
    pub const fn installation_provenance(&self) -> &[u8; 32] {
        &self.installation_provenance
    }
}

/// Code-defined singleton role; there is no caller-selected role value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedPolicyAdministratorV1 {
    _private: (),
}

/// Private facts produced only inside the trusted current-authority adapter.
pub struct VerifiedPolicyAdminAuthorityFacts {
    pub(crate) binding: PolicyAdminSessionBinding,
    pub(crate) installation_provenance: [u8; 32],
}

impl VerifiedPolicyAdminAuthorityFacts {
    pub(crate) fn from_verified_bootstrap(bootstrap: &VerifiedPolicyAdminBootstrap) -> Self {
        Self {
            binding: bootstrap.binding.clone(),
            installation_provenance: bootstrap.installation_provenance,
        }
    }
}

/// Closure-local authority witness. It cannot be forged, cloned, serialized, or sent.
///
/// ```compile_fail
/// use runne_application::project_trust::admin::{CurrentPolicyAdmin, VerifiedPolicyAdminAuthorityFacts};
/// fn forge<'a>(facts: &'a VerifiedPolicyAdminAuthorityFacts) -> CurrentPolicyAdmin<'a> {
///     CurrentPolicyAdmin::new(facts)
/// }
/// ```
///
/// ```compile_fail
/// use runne_application::project_trust::admin::CurrentPolicyAdmin;
/// fn clone_witness<'a>(witness: &'a CurrentPolicyAdmin<'a>) {
///     let _copy = (*witness).clone();
/// }
/// ```
///
/// ```compile_fail
/// use runne_application::project_trust::admin::CurrentPolicyAdmin;
/// fn escape<'a>(witness: &'a CurrentPolicyAdmin<'a>) -> &'static CurrentPolicyAdmin<'static> {
///     witness
/// }
/// ```
pub struct CurrentPolicyAdmin<'a> {
    facts: &'a VerifiedPolicyAdminAuthorityFacts,
    _invariant_not_send_sync: PhantomData<(&'a mut &'a (), Rc<()>)>,
}

impl<'a> CurrentPolicyAdmin<'a> {
    pub(crate) const fn new(facts: &'a VerifiedPolicyAdminAuthorityFacts) -> Self {
        Self {
            facts,
            _invariant_not_send_sync: PhantomData,
        }
    }

    /// Fixed code-defined role proved by current protected bootstrap evidence.
    pub const fn role(&self) -> ManagedPolicyAdministratorV1 {
        ManagedPolicyAdministratorV1 { _private: () }
    }

    /// Full session facts retained by the trusted verifier.
    pub const fn binding(&self) -> &PolicyAdminSessionBinding {
        &self.facts.binding
    }

    /// Stable authenticated subject view for receipt readback only.
    pub const fn authenticated_subject(&self) -> AuthenticatedPolicyAdminSubject<'a> {
        AuthenticatedPolicyAdminSubject { facts: self.facts }
    }

    /// Installation provenance verified from retained protected evidence.
    pub const fn installation_provenance(&self) -> &[u8; 32] {
        &self.facts.installation_provenance
    }
}

/// Authenticated stable identity suitable only for historical receipt reads.
pub struct AuthenticatedPolicyAdminSubject<'a> {
    pub(crate) facts: &'a VerifiedPolicyAdminAuthorityFacts,
}

impl AuthenticatedPolicyAdminSubject<'_> {
    /// Runtime authority bound to the authenticated stable identity.
    pub const fn authority_id(&self) -> &[u8; 16] {
        self.facts.binding.runtime().stable().authority_id()
    }

    /// Runtime event-log lineage bound to the authenticated stable identity.
    pub const fn lineage_id(&self) -> &[u8; 16] {
        self.facts
            .binding
            .runtime()
            .stable()
            .lineage_id()
            .as_bytes()
    }

    /// Stable principal identifier bound to the authenticated stable identity.
    pub fn principal_id(&self) -> &str {
        self.facts
            .binding
            .runtime()
            .stable()
            .principal_id()
            .as_str()
    }

    /// Stable profile identifier bound to the authenticated stable identity.
    pub fn profile_id(&self) -> &str {
        self.facts.binding.runtime().stable().profile_id()
    }

    /// Stable runtime schema digest.
    pub const fn schema_hash(&self) -> &[u8; 32] {
        self.facts.binding.runtime().stable().schema_hash()
    }

    /// Stable runtime capability digest.
    pub const fn capability_digest(&self) -> &[u8; 32] {
        self.facts.binding.runtime().stable().capability_digest()
    }

    /// Provenance authenticated by the protected bootstrap verifier.
    pub const fn installation_provenance(&self) -> &[u8; 32] {
        &self.facts.installation_provenance
    }
}
