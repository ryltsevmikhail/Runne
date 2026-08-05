//! Deterministic virtual process-tree conformance fixture with no native effects.

use std::sync::Mutex;

use gocode_platform_ports::process::{
    MonotonicDeadline, ProcessLifecycleBindingV1, ProcessOwnerVerificationV1, ProcessTreeCleanupV1,
    VerifiedExecutableV1,
};

/// Deterministic platform/control call recorded by the virtual tree fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualProcessCallV1 {
    /// Adapter request revalidation.
    ValidateAndPrepare,
    /// Launch through the adapter-owned prepared value.
    Launch,
    /// Exact graceful tree-control request.
    RequestGraceful,
    /// Bounded monotonic grace wait.
    WaitForGrace,
    /// Bounded observation of exact terminal completion.
    ObserveTerminal,
    /// Exact forced tree termination.
    Terminate,
}

/// Scripted launch behavior of the deterministic virtual tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualLaunchScriptV1 {
    /// Return exact launch evidence.
    Launch,
    /// Return adapter-owned proof that no process started.
    NoProcessStarted,
    /// Return a closed ambiguous launch failure.
    Ambiguous,
}

/// Scripted graceful-control behavior of the deterministic virtual tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualGraceScriptV1 {
    /// Graceful control supplies exact terminal evidence.
    Complete,
    /// Grace expires and forced termination is required.
    Expire,
    /// Graceful control cannot establish exact evidence.
    Ambiguous,
}

/// Closed failure for a poisoned deterministic virtual fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VirtualFixtureErrorV1 {
    /// The fixture state was poisoned and cannot establish deterministic evidence.
    Poisoned,
}

/// In-memory process-tree fixture for conformance tests only.
pub(super) struct VirtualProcessTreeFixtureV1 {
    pub(super) state: Mutex<TreeState>,
}

pub(super) struct TreeState {
    pub(super) calls: Vec<VirtualProcessCallV1>,
    pub(super) prepare_deadline: Option<MonotonicDeadline>,
    pub(super) launch_deadline: Option<MonotonicDeadline>,
    pub(super) launch: VirtualLaunchScriptV1,
    pub(super) grace: VirtualGraceScriptV1,
    pub(super) completion: super::VirtualCompletionScriptV1,
    pub(super) prepare_rejected: bool,
    pub(super) observed_executable: Option<VerifiedExecutableV1>,
    pub(super) graceful_rejected: bool,
    pub(super) force_ambiguous: bool,
    pub(super) launch_evidence_binding: Option<ProcessLifecycleBindingV1>,
    pub(super) control_binding: Option<ProcessLifecycleBindingV1>,
    pub(super) descendants: u32,
    pub(super) unrelated_descendants: u32,
    pub(super) held_binding: Option<ProcessLifecycleBindingV1>,
    pub(super) owner_verification: ProcessOwnerVerificationV1,
    pub(super) tree_cleanup: ProcessTreeCleanupV1,
}

impl Default for VirtualProcessTreeFixtureV1 {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualProcessTreeFixtureV1 {
    /// Creates a virtual tree with no descendants and an exact launch script.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: Mutex::new(TreeState {
                calls: Vec::new(),
                prepare_deadline: None,
                launch_deadline: None,
                launch: VirtualLaunchScriptV1::Launch,
                grace: VirtualGraceScriptV1::Expire,
                completion: super::VirtualCompletionScriptV1::Pending,
                prepare_rejected: false,
                observed_executable: None,
                graceful_rejected: false,
                force_ambiguous: false,
                launch_evidence_binding: None,
                control_binding: None,
                descendants: 0,
                unrelated_descendants: 0,
                held_binding: None,
                owner_verification: ProcessOwnerVerificationV1::Verified,
                tree_cleanup: ProcessTreeCleanupV1::Verified,
            }),
        }
    }

    /// Creates a virtual owned tree and an unrelated tree with independent counters.
    #[must_use]
    pub fn with_descendants(descendants: u32, unrelated_descendants: u32) -> Self {
        let fixture = Self::new();
        if let Ok(mut state) = fixture.state.lock() {
            state.descendants = descendants;
            state.unrelated_descendants = unrelated_descendants;
        }
        fixture
    }

    /// Sets the deterministic launch script.
    pub fn set_launch_script(
        &self,
        script: VirtualLaunchScriptV1,
    ) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .launch = script;
        Ok(())
    }

    /// Sets the deterministic graceful-control script.
    pub fn set_grace_script(
        &self,
        script: VirtualGraceScriptV1,
    ) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .grace = script;
        Ok(())
    }

    /// Makes adapter revalidation fail before launch.
    pub fn reject_prepare(&self) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .prepare_rejected = true;
        Ok(())
    }

    /// Configures the adapter-observed executable for test-only revalidation.
    pub(super) fn set_observed_executable(
        &self,
        executable: VerifiedExecutableV1,
    ) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .observed_executable = Some(executable);
        Ok(())
    }

    /// Makes forced termination ambiguous without modifying virtual counters.
    pub fn make_force_ambiguous(&self) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .force_ambiguous = true;
        Ok(())
    }

    /// Makes launch evidence differ from the held tree without mutating either tree.
    pub fn set_launch_evidence_binding(
        &self,
        binding: ProcessLifecycleBindingV1,
    ) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .launch_evidence_binding = Some(binding);
        Ok(())
    }

    /// Makes exact control target a different held binding after a valid launch.
    pub fn set_control_binding(
        &self,
        binding: ProcessLifecycleBindingV1,
    ) -> Result<(), VirtualFixtureErrorV1> {
        self.state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .control_binding = Some(binding);
        Ok(())
    }

    /// Sets the platform-owned dispositions returned with terminal evidence.
    pub fn set_terminal_verification(
        &self,
        owner: ProcessOwnerVerificationV1,
        cleanup: ProcessTreeCleanupV1,
    ) -> Result<(), VirtualFixtureErrorV1> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?;
        state.owner_verification = owner;
        state.tree_cleanup = cleanup;
        Ok(())
    }

    /// Returns whether a launched fixture currently retains a held binding.
    pub fn has_held_binding(&self) -> Result<bool, VirtualFixtureErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .held_binding
            .is_some())
    }

    /// Returns the deterministic platform/control sequence.
    pub fn call_log(&self) -> Result<Vec<VirtualProcessCallV1>, VirtualFixtureErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .calls
            .clone())
    }

    pub fn prepare_deadline(&self) -> Result<Option<MonotonicDeadline>, VirtualFixtureErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .prepare_deadline)
    }

    pub fn launch_deadline(&self) -> Result<Option<MonotonicDeadline>, VirtualFixtureErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .launch_deadline)
    }

    /// Returns descendants remaining in the owned virtual process tree.
    pub fn descendants(&self) -> Result<u32, VirtualFixtureErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .descendants)
    }

    /// Returns descendants in an unrelated virtual tree.
    pub fn unrelated_descendants(&self) -> Result<u32, VirtualFixtureErrorV1> {
        Ok(self
            .state
            .lock()
            .map_err(|_| VirtualFixtureErrorV1::Poisoned)?
            .unrelated_descendants)
    }

    #[cfg(test)]
    pub(super) fn poison_for_test(&self) {
        let _guard = self.state.lock().expect("healthy test fixture");
        panic!("poison virtual fixture");
    }
}
