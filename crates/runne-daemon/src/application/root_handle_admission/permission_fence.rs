use super::*;
use runne_application::prohibited_content::ProhibitedContentPort;
use runne_store::store::{
    PermissionRootFenceGuardV1, PermissionRootFenceOwnerV1, PermissionRootFenceRequestV1,
    StoreTransaction,
};
use std::collections::HashMap;
use std::sync::MutexGuard;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PermissionStartupError {
    NativeOwnerUnavailable,
    ProtectedRootsUnavailable,
}

impl From<PermissionStartupError> for crate::error::DaemonError {
    fn from(error: PermissionStartupError) -> Self {
        let stage = match error {
            PermissionStartupError::NativeOwnerUnavailable => "initialize native permission owner",
            PermissionStartupError::ProtectedRootsUnavailable => "admit protected roots",
        };
        Self::Bootstrap(stage.into())
    }
}

/// The normal root-admission state allocated before Store and shared by both owners.
#[derive(Clone)]
pub(crate) struct SharedRootAdmissionState {
    pub(super) state: Arc<Mutex<State>>,
}

impl SharedRootAdmissionState {
    pub(crate) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                leases: 0,
                stopped: false,
                pending: HashMap::new(),
                active: HashMap::new(),
            })),
        }
    }
    pub(super) fn same_allocation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.state, &other.state)
    }
}

/// All immutable owners paired before canonical Store publication.
#[derive(Clone)]
pub(crate) struct PermissionStartupBundle {
    root_state: SharedRootAdmissionState,
    root_fence: Arc<dyn PermissionRootFenceOwnerV1>,
    #[cfg(target_os = "linux")]
    admission: Option<Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>>,
    #[cfg(target_os = "linux")]
    native_owner: Option<Arc<runne_platform::local_command_linux::LinuxPermissionOwnerV1>>,
}

impl PermissionStartupBundle {
    #[cfg(target_os = "linux")]
    pub(crate) fn new(
        admission: Option<Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>>,
    ) -> Result<Self, PermissionStartupError> {
        Self::with_native_owner_factory(admission, |admission| {
            runne_platform::local_command_linux::LinuxPermissionOwnerV1::new(admission)
                .map_err(|_| PermissionStartupError::NativeOwnerUnavailable)
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn new(_unused: ()) -> Result<Self, PermissionStartupError> {
        Ok(Self::from_shared_root_state())
    }

    #[cfg(target_os = "linux")]
    fn with_native_owner_factory<F>(
        admission: Option<Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>>,
        create: F,
    ) -> Result<Self, PermissionStartupError>
    where
        F: FnOnce(
            Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>,
        ) -> Result<
            Arc<runne_platform::local_command_linux::LinuxPermissionOwnerV1>,
            PermissionStartupError,
        >,
    {
        let native_owner = admission.clone().map(create).transpose()?;
        Ok(Self::from_shared_root_state(admission, native_owner))
    }

    fn from_shared_root_state(
        #[cfg(target_os = "linux")] admission: Option<
            Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>,
        >,
        #[cfg(target_os = "linux")] native_owner: Option<
            Arc<runne_platform::local_command_linux::LinuxPermissionOwnerV1>,
        >,
    ) -> Self {
        let root_state = SharedRootAdmissionState::new();
        let root_fence: Arc<dyn PermissionRootFenceOwnerV1> =
            Arc::new(PermissionRootFenceAdapter {
                state: Arc::clone(&root_state.state),
            });
        Self {
            root_state,
            root_fence,
            #[cfg(target_os = "linux")]
            admission,
            #[cfg(target_os = "linux")]
            native_owner,
        }
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn prepare(
        db_path: &std::path::Path,
        replay_key_path: &std::path::Path,
    ) -> Result<Self, crate::error::DaemonError> {
        let admission = match super::super::http_startup_support::open_protected_roots(
            db_path,
            replay_key_path,
        ) {
            Some(roots) if !roots.is_empty() => {
                let references = roots.iter().collect::<Vec<_>>();
                Some(Arc::new(
                    runne_platform::local_command_linux::LinuxCompositeScopeAdmission::new(
                        &references,
                    )
                    .map_err(|_| PermissionStartupError::ProtectedRootsUnavailable)?,
                ))
            }
            Some(_) => None,
            None => return Err(PermissionStartupError::ProtectedRootsUnavailable.into()),
        };
        Ok(Self::new(admission)?)
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn prepare(
        _db_path: &std::path::Path,
        _replay_key_path: &std::path::Path,
    ) -> Result<Self, crate::error::DaemonError> {
        Ok(Self::new(())?)
    }

    pub(crate) fn root_state(&self) -> SharedRootAdmissionState {
        self.root_state.clone()
    }
    pub(crate) fn root_fence(&self) -> Arc<dyn PermissionRootFenceOwnerV1> {
        Arc::clone(&self.root_fence)
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn permission_admission(
        &self,
    ) -> Option<Arc<runne_platform::local_command_linux::LinuxCompositeScopeAdmission>> {
        self.admission.clone()
    }

    pub(crate) fn open_store(
        &self,
        db_path: &str,
        writer: runne_store::schema::ManagedConnection,
        reader: runne_store::schema::ManagedConnection,
        authority: runne_application::ports::RuntimeAuthorityId,
        content: Arc<dyn ProhibitedContentPort>,
        trust: Option<Arc<runne_store::ProjectTrustStore>>,
    ) -> Result<StoreTransaction, runne_application::ports::CommitError> {
        #[cfg(target_os = "linux")]
        {
            let paired = validate_store_owner_pair(
                self.admission.is_some(),
                self.native_owner.is_some(),
                trust.is_some(),
            )?;
            if paired {
                if let (Some(trust), Some(native)) = (trust, self.native_owner.clone()) {
                    return StoreTransaction::open_with_connections_and_permission_owner(
                        db_path,
                        writer,
                        reader,
                        authority,
                        content,
                        trust,
                        native,
                        self.root_fence(),
                    );
                }
                return Err(unavailable_store_owner());
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = trust;
        StoreTransaction::open_with_connections(db_path, writer, reader, authority, content)
    }
}

#[cfg(target_os = "linux")]
fn validate_store_owner_pair(
    admission: bool,
    native_owner: bool,
    trust: bool,
) -> Result<bool, runne_application::ports::CommitError> {
    match (admission, native_owner, trust) {
        (false, false, _) => Ok(false),
        (true, true, true) => Ok(true),
        _ => Err(unavailable_store_owner()),
    }
}

fn unavailable_store_owner() -> runne_application::ports::CommitError {
    runne_application::ports::CommitError::StorageFailure(
        runne_application::ports::StorageFailureKind::Unavailable,
    )
}

struct PermissionRootFenceAdapter {
    state: Arc<Mutex<State>>,
}

struct HeldPermissionRoot<'a> {
    _state: MutexGuard<'a, State>,
    files: runne_platform_desktop::LinuxCommandWorkspaceFiles,
    version: u64,
    identity: [u8; 32],
}

impl PermissionRootFenceOwnerV1 for PermissionRootFenceAdapter {
    fn acquire<'a>(
        &'a self,
        request: &PermissionRootFenceRequestV1,
    ) -> Result<Box<dyn PermissionRootFenceGuardV1 + 'a>, runne_application::ports::EventStoreError>
    {
        let state = self
            .state
            .lock()
            .map_err(|_| runne_application::ports::EventStoreError::Unavailable)?;
        if state.stopped {
            return Err(runne_application::ports::EventStoreError::Unavailable);
        }
        let active = state
            .active
            .get(&request.workspace_id())
            .filter(|root| root.version == request.broker_root_version())
            .filter(|root| {
                root.handle.filesystem_identity_digest() == *request.broker_root_identity()
            })
            .filter(|root| active_root_is_current(request.workspace_version(), root.version))
            .ok_or(runne_application::ports::EventStoreError::Unavailable)?;
        let version = active.version;
        let identity = active.handle.filesystem_identity_digest();
        let files = active
            .handle
            .open_linux_command_workspace(std::path::Path::new("."))
            .map_err(|_| runne_application::ports::EventStoreError::Unavailable)?;
        Ok(Box::new(HeldPermissionRoot {
            _state: state,
            files,
            version,
            identity,
        }))
    }
}

impl PermissionRootFenceGuardV1 for HeldPermissionRoot<'_> {
    fn workspace(&self) -> &std::fs::File {
        self.files.workspace()
    }
    fn broker_root_version(&self) -> u64 {
        self.version
    }
    fn broker_root_identity(&self) -> &[u8; 32] {
        &self.identity
    }
}

impl PermissionStartupBundle {
    pub(crate) fn shares_root_state(&self, state: &SharedRootAdmissionState) -> bool {
        self.root_state.same_allocation(state)
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "permission_fence_tests.rs"]
mod tests;
