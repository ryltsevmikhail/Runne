import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface Project {
  readonly id: number
  readonly name: string
  readonly path: string
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
  id: number,
  invoke: Invoke = tauriInvoke,
): Promise<Project | null> {
  const value = await invoke('get_project', { id })
  if (value !== null && !isProject(value)) {
    throw new Error('Invalid project response')
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
    && Number.isSafeInteger(record.id)
    && typeof record.name === 'string'
    && record.name.length > 0
    && typeof record.path === 'string'
    && record.path.length > 0
    && Number.isSafeInteger(record.lastOpenedAt)
  )
}
