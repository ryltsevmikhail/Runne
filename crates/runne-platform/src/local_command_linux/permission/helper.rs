pub use super::helper_types::{
    PermissionHelperBindingObservationV1, PermissionHelperObservationV1,
    PermissionHelperOperationV1, PermissionHelperTargetVersionV1,
};
use super::{
    codec, helper_protocol, lineage::LinuxPermissionPreparationV1,
    terminal::PermissionHelperChildV1,
};
use crate::{
    local_command_linux::{
        LinuxCommandError, LinuxCommandOutputLimitsV1, LinuxCompositeScopeAdmission,
        child::{self, stdio::CommandStdio},
        policy,
        spec::LinuxCommandExecutable,
    },
    process_managed_area::LinuxManagedArea,
};
use runne_application::permission_modes::{
    CompositeEffectScope, IntegrityDigest, NativeScopeAdmissionPort, NativeScopeAdmissionReceipt,
    NetworkScope,
};
use std::{ffi::CString, fs::File, sync::Arc};

#[cfg(all(feature = "test-support", target_os = "linux"))]
#[path = "helper_test_fixture.rs"]
mod helper_test_fixture;

pub(super) fn validate_helper_byte_budget(
    max_bytes: Option<u64>,
    observation: &PermissionHelperObservationV1,
) -> Result<(), LinuxCommandError> {
    if observation.operation() == PermissionHelperOperationV1::Command {
        return if max_bytes.is_none() {
            Ok(())
        } else {
            Err(LinuxCommandError::CompositePolicyUnenforceable)
        };
    }
    let max_bytes = max_bytes.ok_or(LinuxCommandError::CompositePolicyUnenforceable)?;
    let actual_bytes = match observation.operation() {
        PermissionHelperOperationV1::Read => observation
            .target_version()
            .map(|target| target.size)
            .ok_or(LinuxCommandError::Unverified)?,
        PermissionHelperOperationV1::CreateNew | PermissionHelperOperationV1::Replace => {
            u64::try_from(observation.content_length())
                .map_err(|_| LinuxCommandError::Unverified)?
        }
        PermissionHelperOperationV1::List | PermissionHelperOperationV1::Search => 8192,
        PermissionHelperOperationV1::Command => unreachable!("handled above"),
    };
    if actual_bytes > max_bytes {
        return Err(LinuxCommandError::CompositePolicyUnenforceable);
    }
    Ok(())
}

/// Keeps the exact request and its helper-tagged receipt live across human approval.
pub struct PreparedToolHelperV1 {
    admission: Arc<LinuxCompositeScopeAdmission>,
    scope: CompositeEffectScope,
    receipt: NativeScopeAdmissionReceipt,
    request: Vec<u8>,
    parsed: helper_protocol::ParsedHelperRequest,
    workspace: File,
    cwd: File,
    owner_id: [u8; 16],
    generation: u64,
    consumed: bool,
}

impl LinuxPermissionPreparationV1 {
    /// Measures the exact sealed helper for an approval replay check.
    /// # Errors
    /// Rejects unavailable or changed helper identity before releasing effects.
    pub fn tool_helper_executable_digest(&self) -> Result<IntegrityDigest, LinuxCommandError> {
        self.admission.tool_helper_executable_digest()
    }

    /// Returns the protected policy identity for an existing V2 scope profile.
    pub fn protected_control_plane_policy_digest_v2(
        &self,
        network: NetworkScope,
    ) -> Result<IntegrityDigest, LinuxCommandError> {
        self.admission
            .protected_control_plane_policy_digest_v2(network)
    }

    /// Returns the shared native admission registry for a bound local command.
    pub fn invocation_scope_admission_port(&self) -> &dyn NativeScopeAdmissionPort {
        self.admission.as_ref()
    }

    /// Returns the existing native scope registry as the helper admission port.
    pub fn helper_scope_admission_port(&self) -> impl NativeScopeAdmissionPort + '_ {
        self.admission.helper_admission_port()
    }

    /// Admits only a strict request whose operation matches the already admitted scope.
    pub fn prepare_tool_helper(
        &self,
        scope: CompositeEffectScope,
        receipt: NativeScopeAdmissionReceipt,
        request: &[u8],
        workspace: &File,
        cwd: &File,
    ) -> Result<PreparedToolHelperV1, LinuxCommandError> {
        let result = (|| {
            let (owner_id, generation) = self.permission_lineage();
            if generation == 0 || self.admission.permission_lineage() != (owner_id, generation) {
                return Err(LinuxCommandError::Unverified);
            }
            let parsed = helper_protocol::parse_helper_request(request)?;
            validate_helper_byte_budget(scope.budget.max_bytes, &parsed.observation)?;
            helper_protocol::check_helper_target(&parsed, workspace)?;
            if codec::descriptor_identity(workspace)? != codec::descriptor_identity(cwd)? {
                return Err(LinuxCommandError::Unverified);
            }
            self.admission.bind_helper_request(
                &scope,
                receipt,
                parsed.observation.operation,
                helper_protocol::helper_request_digest(request),
                workspace,
                cwd,
            )?;
            Ok(PreparedToolHelperV1 {
                admission: Arc::clone(&self.admission),
                scope,
                receipt,
                request: request.to_vec(),
                parsed,
                workspace: workspace
                    .try_clone()
                    .map_err(|_| LinuxCommandError::Unavailable)?,
                cwd: cwd
                    .try_clone()
                    .map_err(|_| LinuxCommandError::Unavailable)?,
                owner_id,
                generation,
                consumed: false,
            })
        })();
        if result.is_err() {
            let _ = self.admission.revoke(receipt);
        }
        result
    }
}

impl PreparedToolHelperV1 {
    /// Returns the one-shot native admission receipt held across approval.
    pub const fn native_receipt(&self) -> NativeScopeAdmissionReceipt {
        self.receipt
    }
    /// Returns the parsed facts from the exact request retained for execution.
    pub fn observation(&self) -> &PermissionHelperObservationV1 {
        &self.parsed.observation
    }

    /// Replays the byte-identical request into the existing gated child executor once.
    pub fn spawn_helper<'area>(
        mut self,
        live_request: &[u8],
        area: &'area LinuxManagedArea,
        limits: LinuxCommandOutputLimitsV1,
    ) -> Result<PermissionHelperChildV1<'area>, LinuxCommandError> {
        if live_request != self.request
            || helper_protocol::helper_request_digest(live_request)
                != self.parsed.observation.request_digest
            || !helper_protocol::helper_is_current(self.parsed.observation.expires_at_unix_ms)?
            || limits.stdout_bytes() > 16 * 1024
            || limits.stderr_bytes() > 4 * 1024
        {
            child::helper_stage("helper.request");
            return Err(LinuxCommandError::Unverified);
        }
        helper_protocol::check_helper_target(&self.parsed, &self.workspace)
            .inspect_err(|_| child::helper_stage("helper.target"))?;
        let image = self
            .admission
            .helper_image()
            .inspect_err(|_| child::helper_stage("helper.image"))?;
        let executable = LinuxCommandExecutable::SealedSnapshot(image);
        policy::validate_descriptors(executable.file(), &self.workspace, &self.cwd)
            .inspect_err(|_| child::helper_stage("helper.descriptors"))?;
        let mut filesystem = policy::native_fs_profile(&self.scope.filesystem.permissions)
            .inspect_err(|_| child::helper_stage("helper.filesystem"))?;
        filesystem.metadata_allowed = false;
        let ruleset = policy::build_helper_ruleset(&self.workspace, &executable, filesystem)
            .inspect_err(|_| child::helper_stage("helper.ruleset"))?;
        let stdio = CommandStdio::bounded(&self.request, limits)
            .inspect_err(|_| child::helper_stage("helper.stdio"))?;
        if area.is_populated().map_err(|_| LinuxCommandError::Area)? {
            return Err(LinuxCommandError::Area);
        }
        let argv = [
            CString::new("runned").map_err(|_| LinuxCommandError::Invalid)?,
            CString::new("--safe-tool-helper-v1").map_err(|_| LinuxCommandError::Invalid)?,
        ];
        #[cfg(all(feature = "test-support", target_os = "linux"))]
        let env = helper_test_fixture::approved_target_race_environment();
        #[cfg(not(all(feature = "test-support", target_os = "linux")))]
        let env: Vec<CString> = Vec::new();
        let (prepared, admitted_at) = self
            .admission
            .consume_helper_request(
                &self.scope,
                self.receipt,
                self.parsed.observation.operation,
                self.parsed.observation.request_digest,
                &self.workspace,
                &self.cwd,
            )
            .inspect_err(|_| child::helper_stage("helper.consume"))?;
        self.consumed = true;
        let child = child::spawn(child::SpawnSpec {
            exe: executable.file(),
            workspace: &self.workspace,
            cwd: &self.cwd,
            ruleset: Some(&ruleset),
            argv: &argv,
            env: &env,
            area,
            stdio,
            composite: if self.parsed.observation.operation == PermissionHelperOperationV1::Command
            {
                Some(&prepared)
            } else {
                None
            },
            network_none: true,
            filesystem_profile: Some(filesystem),
        })
        .inspect_err(|_| child::helper_stage("helper.spawn"))?;
        Ok(PermissionHelperChildV1 {
            child,
            area,
            admission: Arc::clone(&self.admission),
            scope: self.scope.clone(),
            receipt: self.receipt,
            request: self.request.clone(),
            parsed: self.parsed.clone(),
            workspace: self
                .workspace
                .try_clone()
                .map_err(|_| LinuxCommandError::Unavailable)?,
            cwd: self
                .cwd
                .try_clone()
                .map_err(|_| LinuxCommandError::Unavailable)?,
            prepared,
            admitted_at,
            owner_id: self.owner_id,
            generation: self.generation,
            area_identity: area.identity().to_bytes(),
        })
    }
}
impl Drop for PreparedToolHelperV1 {
    fn drop(&mut self) {
        if !self.consumed {
            let _ = self.admission.revoke(self.receipt);
        }
    }
}

impl LinuxCompositeScopeAdmission {
    /// Measures the sealed helper executable actually passed to the process gate.
    /// This identifies the helper, not binaries named by its approved argv payload.
    ///
    /// # Errors
    /// Rejects absent, unsealed, or unreadable helper images before approval.
    pub fn tool_helper_executable_digest(&self) -> Result<IntegrityDigest, LinuxCommandError> {
        let image = self.helper_image()?;
        image.validate_seals()?;
        codec::file_digest(image.file()).map(IntegrityDigest::from_bytes)
    }
}
