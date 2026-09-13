import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface Project {
  readonly projectId: string
  readonly workspaceId: string
  readonly displayName: string
  readonly lastOpenedAt: number
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export interface DirectorySelection {
  readonly reference: string
}

export interface PreparedWorkspace {
  readonly reference: string
  readonly summary: {
    readonly displayName: 'Selected folder'
  }
}

export interface WorkspacePreparation {
  readonly selection: string
  readonly rendererGeneration: number
  readonly requestId: string
  readonly workspaceId: string
  readonly expectedVersion: number
}

export interface PreparedWorkspaceOpenRequest {
  readonly prepared: string
  readonly rendererGeneration: number
  readonly requestId: string
}

export async function acquireRendererGeneration(
  invoke: Invoke = tauriInvoke,
): Promise<number> {
  const value = await invoke('acquire_renderer_generation')
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new Error('Invalid renderer generation response')
  }
  return value
}

export async function listProjects(invoke: Invoke = tauriInvoke): Promise<readonly Project[]> {
  const value = await invoke('list_projects')
  if (!Array.isArray(value) || !value.every(isProject)) {
    throw new Error('Invalid projects response')
  }
  return value
}

export async function prepareSelectedWorkspace(
  request: WorkspacePreparation,
  invoke: Invoke = tauriInvoke,
): Promise<PreparedWorkspace> {
  const value = await invoke('prepare_selected_workspace', { request })
  if (!isPreparedWorkspace(value)) {
    throw new Error('Invalid prepared workspace response')
  }
  return value
}

export async function openSelectedWorkspace(
  request: PreparedWorkspaceOpenRequest,
  invoke: Invoke = tauriInvoke,
): Promise<void> {
  await invoke('open_selected_workspace', { request })
}

export async function retryOpenSelectedWorkspace(
  request: PreparedWorkspaceOpenRequest,
  invoke: Invoke = tauriInvoke,
): Promise<void> {
  await invoke('retry_open_selected_workspace', { request })
}

export async function requestDirectorySelection(
  requestId: string,
  rendererGeneration: number,
  invoke: Invoke = tauriInvoke,
): Promise<DirectorySelection | null> {
  const value = await invoke('request_directory_selection', {
    requestId,
    rendererGeneration,
  })
  if (value === null) {
    return null
  }
  if (!isDirectorySelection(value)) {
    throw new Error('Invalid directory selection response')
  }
  return value
}

export async function getProject(
  projectId: string,
  invoke: Invoke = tauriInvoke,
): Promise<readonly Project[]> {
  if (!isCanonicalRuntimeId(projectId)) {
    throw new Error('Invalid project identifier')
  }
  const value = await invoke('get_project', { projectId })
  if (!Array.isArray(value) || !value.every(isProject)) {
    throw new Error('Invalid project response')
  }
  return value
}

export async function getWorkspace(
  workspaceId: string,
  invoke: Invoke = tauriInvoke,
): Promise<Project | null> {
  if (!isCanonicalRuntimeId(workspaceId)) {
    throw new Error('Invalid workspace identifier')
  }
  const value = await invoke('get_workspace', { workspaceId })
  if (value !== null && !isProject(value)) {
    throw new Error('Invalid workspace response')
  }
  return value
}

function isDirectorySelection(value: unknown): value is DirectorySelection {
  return (
    typeof value === 'object'
    && value !== null
    && !Array.isArray(value)
    && Object.keys(value as Record<string, unknown>).length === 1
    && typeof (value as Record<string, unknown>).reference === 'string'
    && /^[a-f0-9]{64}$/.test((value as Record<string, unknown>).reference as string)
  )
}

function isPreparedWorkspace(value: unknown): value is PreparedWorkspace {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  const summary = record.summary
  return (
    Object.keys(record).length === 2
    && typeof record.reference === 'string'
    && /^[a-f0-9]{64}$/.test(record.reference)
    && typeof summary === 'object'
    && summary !== null
    && !Array.isArray(summary)
    && Object.keys(summary as Record<string, unknown>).length === 1
    && (summary as Record<string, unknown>).displayName === 'Selected folder'
  )
}

function isProject(value: unknown): value is Project {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    Object.keys(record).length === 4
    && isCanonicalRuntimeId(record.projectId)
    && isCanonicalRuntimeId(record.workspaceId)
    && typeof record.displayName === 'string'
    && record.displayName.length > 0
    && record.displayName.length <= 256
    && !/[\p{Cc}\p{Cf}]/u.test(record.displayName)
    && typeof record.lastOpenedAt === 'number'
    && Number.isSafeInteger(record.lastOpenedAt)
    && record.lastOpenedAt >= 0
  )
}

export function isCanonicalRuntimeId(value: unknown): value is string {
  return typeof value === 'string'
    && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
}
