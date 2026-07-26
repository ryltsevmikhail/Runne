import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface Project {
  readonly id: number
  readonly name: string
  readonly path: string
  readonly lastOpenedAt: number
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

export async function listProjects(invoke: Invoke = tauriInvoke): Promise<readonly Project[]> {
  const value = await invoke('list_projects')
  if (!Array.isArray(value) || !value.every(isProject)) {
    throw new Error('Invalid projects response')
  }
  return value
}

export async function openLocalProject(
  path: string,
  invoke: Invoke = tauriInvoke,
): Promise<Project> {
  const value = await invoke('open_local_project', { path })
  if (!isProject(value)) {
    throw new Error('Invalid project response')
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
