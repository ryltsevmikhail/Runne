//! In-process versioned repository for canonical Project and Workspace state.

use gocode_application::ports::{
    ProjectWorkspaceRepository, ProjectWorkspaceRepositoryError as Error,
};
use gocode_domain::{
    id::{CommandId, IdempotencyKey, ProjectId, WorkspaceId},
    project_workspace::{Project, ProjectWorkspaceError, Workspace},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

#[derive(Clone, Default)]
pub struct ProjectWorkspaceStore {
    state: Arc<Mutex<State>>,
}
#[derive(Default)]
struct State {
    projects: HashMap<ProjectId, Owned<Project>>,
    workspaces: HashMap<WorkspaceId, Owned<Workspace>>,
    receipts: HashMap<ReceiptKey, Receipt>,
}
struct Owned<T> {
    principal: String,
    value: T,
}
#[derive(Hash, PartialEq, Eq)]
struct ReceiptKey {
    principal: String,
    operation: u8,
    aggregate: [u8; 16],
    key: String,
}
enum Receipt {
    Project {
        command: CommandId,
        value: Result<Project, Error>,
    },
    Workspace {
        command: CommandId,
        value: Result<Workspace, Error>,
    },
    Delete {
        command: CommandId,
        value: Result<u64, Error>,
    },
}

impl ProjectWorkspaceStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[rustfmt::skip]
impl ProjectWorkspaceRepository for ProjectWorkspaceStore {
fn create_project(&self, p: &str, c: CommandId, k: &IdempotencyKey, project: Project) -> Result<Project, Error> {
    let id = project.id(); let mut s = lock(&self.state)?; if let Some(r) = project_replay(&s, p, 1, id.into_bytes(), k, c) { return r; }
    let result = if let std::collections::hash_map::Entry::Vacant(entry) = s.projects.entry(id) { entry.insert(Owned { principal: p.into(), value: project.clone() }); Ok(project) } else { Err(Error::Conflict) };
    store_project(&mut s, p, 1, id.into_bytes(), k, c, result.clone()); result
}
fn archive_project(&self, p: &str, c: CommandId, k: &IdempotencyKey, id: ProjectId, v: u64) -> Result<Project, Error> { project_change(&self.state, p, c, k, id, v, 2, Project::archive) }
fn restore_project(&self, p: &str, c: CommandId, k: &IdempotencyKey, id: ProjectId, v: u64) -> Result<Project, Error> { project_change(&self.state, p, c, k, id, v, 7, Project::restore) }
fn delete_project(&self, p: &str, c: CommandId, k: &IdempotencyKey, id: ProjectId, v: u64) -> Result<u64, Error> {
    let mut s = lock(&self.state)?; if let Some(r) = delete_replay(&s, p, id.into_bytes(), k, c) { return r; }
    let result = match s.projects.get(&id) { None => Err(Error::NotFound), Some(x) if x.principal != p => Err(Error::Forbidden), Some(x) if x.value.version() != v || s.workspaces.values().any(|w| w.value.project_id() == id) => Err(Error::Conflict), Some(_) => { s.projects.remove(&id); v.checked_add(1).ok_or(Error::InvariantViolation) } };
    store_delete(&mut s, p, id.into_bytes(), k, c, result); result
}
fn create_workspace(&self, p: &str, c: CommandId, k: &IdempotencyKey, workspace: Workspace) -> Result<Workspace, Error> {
    let id = workspace.id(); let mut s = lock(&self.state)?; if let Some(r) = workspace_replay(&s, p, 4, id.into_bytes(), k, c) { return r; }
    let result = match s.projects.get(&workspace.project_id()) { None => Err(Error::NotFound), Some(x) if x.principal != p => Err(Error::Forbidden), Some(x) if x.value.archived() || s.workspaces.contains_key(&id) => Err(Error::Conflict), Some(_) => { s.workspaces.insert(id, Owned { principal: p.into(), value: workspace.clone() }); Ok(workspace) } };
    store_workspace(&mut s, p, 4, id.into_bytes(), k, c, result.clone()); result
}
fn open_workspace(&self, p: &str, c: CommandId, k: &IdempotencyKey, id: WorkspaceId, v: u64) -> Result<Workspace, Error> { workspace_change(&self.state, p, c, k, id, v, 5, Workspace::open) }
fn bind_workspace_root(&self, p: &str, c: CommandId, k: &IdempotencyKey, id: WorkspaceId, v: u64) -> Result<Workspace, Error> { workspace_change(&self.state, p, c, k, id, v, 6, Workspace::bind_root) }
fn list_projects(&self, p: &str) -> Result<Vec<Project>, Error> { Ok(lock(&self.state)?.projects.values().filter(|x| x.principal == p).map(|x| x.value.clone()).collect()) }
fn get_project(&self, p: &str, id: ProjectId) -> Result<Project, Error> { let s = lock(&self.state)?; owned_project(&s, p, id) }
fn list_workspaces(&self, p: &str, id: ProjectId) -> Result<Vec<Workspace>, Error> { let s = lock(&self.state)?; owned_project(&s, p, id)?; Ok(s.workspaces.values().filter(|x| x.principal == p && x.value.project_id() == id).map(|x| x.value.clone()).collect()) }
fn get_workspace(&self, p: &str, id: WorkspaceId) -> Result<Workspace, Error> { match lock(&self.state)?.workspaces.get(&id) { None => Err(Error::NotFound), Some(x) if x.principal != p => Err(Error::Forbidden), Some(x) => Ok(x.value.clone()) } }
}

#[rustfmt::skip]
fn lock(state: &Arc<Mutex<State>>) -> Result<std::sync::MutexGuard<'_, State>, Error> { state.lock().map_err(|_| Error::Unavailable) }
#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
fn project_change(state: &Arc<Mutex<State>>, p: &str, c: CommandId, k: &IdempotencyKey, id: ProjectId, v: u64, op: u8, action: fn(&mut Project) -> Result<(), ProjectWorkspaceError>) -> Result<Project, Error> {
    let mut s = lock(state)?; if let Some(r) = project_replay(&s, p, op, id.into_bytes(), k, c) { return r; }
    let result = match s.projects.get_mut(&id) { None => Err(Error::NotFound), Some(x) if x.principal != p => Err(Error::Forbidden), Some(x) if x.value.version() != v => Err(Error::Conflict), Some(x) => action(&mut x.value).map_err(|_| Error::Conflict).map(|_| x.value.clone()) };
    store_project(&mut s, p, op, id.into_bytes(), k, c, result.clone()); result
}
#[rustfmt::skip]
#[allow(clippy::too_many_arguments)]
fn workspace_change(state: &Arc<Mutex<State>>, p: &str, c: CommandId, k: &IdempotencyKey, id: WorkspaceId, v: u64, op: u8, action: fn(&mut Workspace) -> Result<(), ProjectWorkspaceError>) -> Result<Workspace, Error> {
    let mut s = lock(state)?; if let Some(r) = workspace_replay(&s, p, op, id.into_bytes(), k, c) { return r; }
    let result = match s.workspaces.get_mut(&id) { None => Err(Error::NotFound), Some(x) if x.principal != p => Err(Error::Forbidden), Some(x) if x.value.version() != v => Err(Error::Conflict), Some(x) => action(&mut x.value).map_err(|_| Error::Conflict).map(|_| x.value.clone()) };
    store_workspace(&mut s, p, op, id.into_bytes(), k, c, result.clone()); result
}
#[rustfmt::skip]
fn owned_project(s: &State, p: &str, id: ProjectId) -> Result<Project, Error> { match s.projects.get(&id) { None => Err(Error::NotFound), Some(x) if x.principal != p => Err(Error::Forbidden), Some(x) => Ok(x.value.clone()) } }
#[rustfmt::skip]
fn key(p: &str, op: u8, id: [u8; 16], k: &IdempotencyKey) -> ReceiptKey { ReceiptKey { principal: p.into(), operation: op, aggregate: id, key: k.as_str().into() } }
#[rustfmt::skip]
fn project_replay(s: &State, p: &str, op: u8, id: [u8; 16], k: &IdempotencyKey, c: CommandId) -> Option<Result<Project, Error>> { match s.receipts.get(&key(p, op, id, k)) { Some(Receipt::Project { command, value }) if *command == c => Some(value.clone()), Some(_) => Some(Err(Error::Conflict)), None => None } }
#[rustfmt::skip]
fn workspace_replay(s: &State, p: &str, op: u8, id: [u8; 16], k: &IdempotencyKey, c: CommandId) -> Option<Result<Workspace, Error>> { match s.receipts.get(&key(p, op, id, k)) { Some(Receipt::Workspace { command, value }) if *command == c => Some(value.clone()), Some(_) => Some(Err(Error::Conflict)), None => None } }
#[rustfmt::skip]
fn delete_replay(s: &State, p: &str, id: [u8; 16], k: &IdempotencyKey, c: CommandId) -> Option<Result<u64, Error>> { match s.receipts.get(&key(p, 3, id, k)) { Some(Receipt::Delete { command, value }) if *command == c => Some(*value), Some(_) => Some(Err(Error::Conflict)), None => None } }
#[rustfmt::skip]
fn store_project(s: &mut State, p: &str, op: u8, id: [u8; 16], k: &IdempotencyKey, c: CommandId, value: Result<Project, Error>) { s.receipts.insert(key(p, op, id, k), Receipt::Project { command: c, value }); }
#[rustfmt::skip]
fn store_workspace(s: &mut State, p: &str, op: u8, id: [u8; 16], k: &IdempotencyKey, c: CommandId, value: Result<Workspace, Error>) { s.receipts.insert(key(p, op, id, k), Receipt::Workspace { command: c, value }); }
#[rustfmt::skip]
fn store_delete(s: &mut State, p: &str, id: [u8; 16], k: &IdempotencyKey, c: CommandId, value: Result<u64, Error>) { s.receipts.insert(key(p, 3, id, k), Receipt::Delete { command: c, value }); }
