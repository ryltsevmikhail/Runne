use super::*;
use gocode_api::{
    LaunchSecret, ProtectedActivationKeys, RootAdmissionAuthenticator, RootAdmissionRequest,
};
use rusqlite::Connection;
use std::path::Path;
use std::sync::mpsc::Sender;
use std::time::Duration;

pub(super) struct MutableAuthority(Arc<Mutex<MutableState>>);
struct MutableState {
    context: RootAdmissionVerificationContext,
    leases: usize,
}
pub(super) struct MutableLease(Arc<Mutex<MutableState>>);

impl MutableAuthority {
    pub(super) fn new(context: RootAdmissionVerificationContext) -> Self {
        Self(Arc::new(Mutex::new(MutableState { context, leases: 0 })))
    }
    pub(super) fn advance_clock(&self, now: u64) {
        let mut state = self.0.lock().unwrap();
        let value = &state.context;
        state.context = RootAdmissionVerificationContext::new(
            value.authority_digest(),
            value.session_id(),
            value.launch_generation(),
            value.principal_digest(),
            value.capability_version(),
            value.policy_version(),
            value.gate_epoch(),
            now,
        )
        .unwrap();
    }
    pub(super) fn rotate(
        &self,
        context: RootAdmissionVerificationContext,
    ) -> Result<(), RootAdmissionVerifierError> {
        let mut state = self.0.lock().unwrap();
        if state.leases != 0 {
            return Err(RootAdmissionVerifierError::Rejected);
        }
        state.context = context;
        Ok(())
    }
}

impl Clone for MutableAuthority {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl CurrentRootAdmissionContext for MutableAuthority {
    type Lease = MutableLease;
    fn acquire_root_admission_lease(&self) -> Result<MutableLease, RootAdmissionVerifierError> {
        self.0.lock().unwrap().leases += 1;
        Ok(MutableLease(self.0.clone()))
    }
}
impl RootAdmissionLease for MutableLease {
    fn current_root_admission_context(
        &self,
    ) -> Result<RootAdmissionVerificationContext, RootAdmissionVerifierError> {
        Ok(self.0.lock().unwrap().context.clone())
    }
}
impl Drop for MutableLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.leases -= 1;
        }
    }
}

pub(super) fn keys() -> ProtectedActivationKeys {
    LaunchSecret::from_bytes([7; 32]).unwrap().derive_keys()
}
pub(super) fn issue(
    keys: &ProtectedActivationKeys,
    context: RootAdmissionVerificationContext,
    workspace: WorkspaceId,
    nonce: u8,
    expiry: u64,
    digest: u8,
) -> gocode_api::RootHandleAdmission {
    RootAdmissionAuthenticator::from_protected_activation(keys)
        .issue(
            RootAdmissionRequest::new(
                context,
                workspace,
                1,
                [9; 32],
                [nonce; 16],
                expiry,
                [digest; 32],
            )
            .unwrap(),
        )
        .unwrap()
}

pub(super) struct AuthenticatorVerifier {
    authenticator: RootAdmissionAuthenticator,
    entered: Option<Sender<()>>,
}
impl RootAdmissionVerifier for AuthenticatorVerifier {
    fn verify_root_admission(
        &self,
        admission: gocode_api::RootHandleAdmission,
    ) -> Result<gocode_api::VerifiedRootAdmissionClaims, RootAdmissionVerifierError> {
        if let Some(sender) = &self.entered {
            sender
                .send(())
                .map_err(|_| RootAdmissionVerifierError::Unavailable)?;
        }
        self.authenticator
            .verify(admission)
            .map_err(|_| RootAdmissionVerifierError::Rejected)
    }
}

pub(super) fn authenticated_host(
    store: StoreTransaction,
    authority: MutableAuthority,
    keys: &ProtectedActivationKeys,
    entered: Option<Sender<()>>,
) -> RuntimeProjectWorkspaceHost<ProjectWorkspaceStore, MutableAuthority, AuthenticatorVerifier> {
    RuntimeProjectWorkspaceHost::new(
        ProjectWorkspaceStore::from_store(store),
        authority,
        AuthenticatorVerifier {
            authenticator: RootAdmissionAuthenticator::from_protected_activation(keys),
            entered,
        },
    )
}

type NonceRow = (String, Vec<u8>, String, Vec<u8>, i64, Vec<u8>);
type ReceiptRow = (
    Vec<u8>,
    String,
    String,
    i64,
    i64,
    Vec<u8>,
    String,
    Vec<u8>,
    Vec<u8>,
    i64,
);

#[derive(Debug, PartialEq, Eq)]
pub(super) struct DatabaseState {
    workspaces: Vec<(Vec<u8>, i64, i64, i64)>,
    nonces: Vec<NonceRow>,
    receipts: Vec<ReceiptRow>,
}
pub(super) fn database_state(path: &Path) -> DatabaseState {
    let connection = Connection::open(path).unwrap();
    let workspaces = connection
        .prepare("SELECT workspace_id, version, open, live FROM workspaces ORDER BY workspace_id")
        .unwrap()
        .query_map([], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    let nonces = connection.prepare("SELECT runtime_authority_id, nonce, principal_id, workspace_id, expected_version, admission_digest FROM root_admission_nonces ORDER BY runtime_authority_id, nonce").unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    let receipts = connection.prepare("SELECT command_id, runtime_authority_id, principal_id, operation, aggregate_kind, aggregate_id, idempotency_key, semantic_fingerprint, outcome, committed_at FROM project_workspace_command_receipts ORDER BY command_id").unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?, row.get(7)?, row.get(8)?, row.get(9)?))).unwrap().collect::<rusqlite::Result<_>>().unwrap();
    DatabaseState {
        workspaces,
        nonces,
        receipts,
    }
}

#[tokio::test]
async fn expiry_is_checked_after_the_writer_and_rotation_is_rejected_by_the_live_lease() {
    let (directory, store) = store();
    let path = directory.path().join("admission.sqlite");
    let workspace = WORKSPACE.parse().unwrap();
    create_workspace(store.clone(), workspace).await;
    let authority = MutableAuthority::new(admission_context());
    let keys = keys();
    let admission = issue(&keys, admission_context(), workspace, 81, 200, 81);
    let (entered, receiver) = std::sync::mpsc::channel();
    let host = authenticated_host(store, authority.clone(), &keys, Some(entered));
    let before = database_state(&path);
    let writer = Connection::open(&path).unwrap();
    writer.execute_batch("BEGIN IMMEDIATE").unwrap();
    let worker = std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(host.bind_workspace_root(
                command("owner", 81),
                BindWorkspaceRootCommand {
                    workspace_id: workspace,
                    expected_version: 1,
                    root_admission: admission,
                },
            ))
    });
    receiver.recv_timeout(Duration::from_secs(2)).unwrap();
    authority.advance_clock(201);
    assert_eq!(
        authority.rotate(admission_context()),
        Err(RootAdmissionVerifierError::Rejected)
    );
    writer.execute_batch("COMMIT").unwrap();
    assert_eq!(
        worker.join().unwrap(),
        Err(ProjectWorkspaceHostError::Forbidden)
    );
    assert_eq!(database_state(&path), before);
    assert_eq!(authority.rotate(admission_context()), Ok(()));
}
