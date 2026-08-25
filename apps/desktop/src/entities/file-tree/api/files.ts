import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type WorkspaceFileKind = 'file' | 'directory'

export interface WorkspaceFileEntry {
  readonly path: string
  readonly kind: WorkspaceFileKind
  readonly sizeBytes: number
}

export interface WorkspaceFilePage {
  readonly items: readonly WorkspaceFileEntry[]
}

export interface WorkspaceFileContent {
  readonly path: string
  readonly content: string
  readonly sizeBytes: number
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const MAX_PATH_BYTES = 4096
const MAX_PAGE_SIZE = 200
const MAX_CONTENT_BYTES = 1_048_576

export async function listWorkspaceFiles(
  workspaceId: string,
  path = '',
  limit = 50,
  invoke: Invoke = tauriInvoke,
): Promise<WorkspaceFilePage> {
  validateId(workspaceId)
  validatePath(path, true)
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
    throw new Error('Invalid workspace file limit')
  }
  const value = await invoke('list_workspace_files', { workspaceId, path, limit })
  if (!isPage(value, limit)) {
    throw new Error('Invalid workspace file page')
  }
  return value
}

export async function readWorkspaceFile(
  workspaceId: string,
  path: string,
  invoke: Invoke = tauriInvoke,
): Promise<WorkspaceFileContent> {
  validateId(workspaceId)
  validatePath(path, false)
  const value = await invoke('read_workspace_file', { workspaceId, path })
  if (!isContent(value, path)) {
    throw new Error('Invalid workspace file content')
  }
  return value
}

function isPage(value: unknown, limit: number): value is WorkspaceFilePage {
  if (!isRecord(value) || !Array.isArray(value.items) || value.items.length > limit) {
    return false
  }
  if (!value.items.every(isEntry)) {
    return false
  }
  const items = value.items as WorkspaceFileEntry[]
  return items.every((entry, index) => {
    const previous = items[index - 1]
    return previous === undefined || previous.path < entry.path
  })
}

function isEntry(value: unknown): value is WorkspaceFileEntry {
  return isRecord(value)
    && Object.keys(value).length === 3
    && typeof value.path === 'string'
    && isCanonicalPath(value.path, false)
    && (value.kind === 'file' || value.kind === 'directory')
    && typeof value.sizeBytes === 'number'
    && Number.isSafeInteger(value.sizeBytes)
    && value.sizeBytes >= 0
}

function isContent(value: unknown, path: string): value is WorkspaceFileContent {
  return isRecord(value)
    && Object.keys(value).length === 3
    && value.path === path
    && typeof value.content === 'string'
    && new TextEncoder().encode(value.content).length <= MAX_CONTENT_BYTES
    && typeof value.sizeBytes === 'number'
    && Number.isSafeInteger(value.sizeBytes)
    && value.sizeBytes === new TextEncoder().encode(value.content).length
}

function validateId(value: string): void {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) {
    throw new Error('Invalid workspace identifier')
  }
}

function validatePath(value: string, allowEmpty: boolean): void {
  if (!isCanonicalPath(value, allowEmpty)) {
    throw new Error('Invalid workspace file path')
  }
}

function isCanonicalPath(value: string, allowEmpty: boolean): boolean {
  const bytes = new TextEncoder().encode(value).length
  return bytes <= MAX_PATH_BYTES
    && (allowEmpty || value.length > 0)
    && !value.startsWith('/')
    && !value.includes('\\')
    && !Array.from(value).some(character => character.charCodeAt(0) < 0x20)
    && (value.length === 0
      || !value.split('/').some(part => part.length === 0 || part === '.' || part === '..'))
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}
