import { invoke as tauriInvoke } from '@tauri-apps/api/core'

import { isCanonicalRuntimeId } from './projects'

export interface CanonicalProject {
  readonly projectId: string
  readonly displayName: string
  readonly version: number
  readonly archived: boolean
}

export interface CanonicalWorkspace {
  readonly workspaceId: string
  readonly projectId: string
  readonly displayName: string
  readonly version: number
  readonly open: boolean
}

export interface CanonicalProjectDetails {
  readonly project: CanonicalProject
  readonly workspaces: readonly CanonicalWorkspace[]
}

export interface CanonicalWorkspaceMutationAck {
  readonly workspaceId: string
  readonly newVersion: number
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function listCanonicalProjects(
  invoke: Invoke = tauriInvoke,
): Promise<readonly CanonicalProject[]> {
  const value = await invoke('list_canonical_projects')
  if (!Array.isArray(value) || !value.every(isCanonicalProject)) {
    throw new Error('Invalid canonical projects response')
  }
  return value
}

export async function getCanonicalProject(
  projectId: string,
  invoke: Invoke = tauriInvoke,
): Promise<CanonicalProjectDetails> {
  if (!isCanonicalRuntimeId(projectId)) {
    throw new Error('Invalid canonical project identifier')
  }
  const value = await invoke('get_canonical_project', { projectId })
  if (!isCanonicalProjectDetails(value, projectId)) {
    throw new Error('Invalid canonical project response')
  }
  return value
}

export async function createCanonicalWorkspace(
  projectId: string,
  displayName: string,
  invoke: Invoke = tauriInvoke,
): Promise<CanonicalWorkspaceMutationAck> {
  if (!isCanonicalRuntimeId(projectId) || !displayNameValue(displayName)) {
    throw new Error('Invalid canonical workspace mutation')
  }
  const value = await invoke('create_runtime_workspace', { projectId, displayName })
  if (!isCanonicalWorkspaceMutationAck(value)) {
    throw new Error('Invalid canonical workspace mutation response')
  }
  return value
}

export async function getCanonicalWorkspace(
  workspaceId: string,
  invoke: Invoke = tauriInvoke,
): Promise<CanonicalWorkspace> {
  if (!isCanonicalRuntimeId(workspaceId)) {
    throw new Error('Invalid canonical workspace identifier')
  }
  const value = await invoke('get_canonical_workspace', { workspaceId })
  if (!isCanonicalWorkspace(value) || value.workspaceId !== workspaceId) {
    throw new Error('Invalid canonical workspace response')
  }
  return value
}

function isCanonicalProjectDetails(value: unknown, projectId: string): value is CanonicalProjectDetails {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return Object.keys(record).length === 2
    && isCanonicalProject(record.project)
    && record.project.projectId === projectId
    && Array.isArray(record.workspaces)
    && record.workspaces.every(workspace => isCanonicalWorkspace(workspace)
      && workspace.projectId === projectId)
}

function isCanonicalProject(value: unknown): value is CanonicalProject {
  return closed(value, ['projectId', 'displayName', 'version', 'archived'])
    && isCanonicalRuntimeId(value.projectId)
    && displayName(value.displayName)
    && version(value.version)
    && typeof value.archived === 'boolean'
}

function isCanonicalWorkspace(value: unknown): value is CanonicalWorkspace {
  return closed(value, ['workspaceId', 'projectId', 'displayName', 'version', 'open'])
    && isCanonicalRuntimeId(value.workspaceId)
    && isCanonicalRuntimeId(value.projectId)
    && displayName(value.displayName)
    && version(value.version)
    && typeof value.open === 'boolean'
}

function closed(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every(key => Object.hasOwn(value, key))
}

function displayName(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= 256
    && !/[\p{Cc}\p{Cf}]/u.test(value)
}

function displayNameValue(value: unknown): value is string {
  return displayName(value)
}

function isCanonicalWorkspaceMutationAck(value: unknown): value is CanonicalWorkspaceMutationAck {
  return closed(value, ['workspaceId', 'newVersion'])
    && isCanonicalRuntimeId(value.workspaceId)
    && version(value.newVersion)
}

function version(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value > 0
}
