import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export interface EditorLaunchReceipt {
  readonly workspaceId: string
  readonly target: 'system_default'
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>

const ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const MAX_PATH_BYTES = 4096

export async function openWorkspaceEditor(
  workspaceId: string,
  relativePath: string,
  invoke: Invoke = tauriInvoke,
): Promise<EditorLaunchReceipt> {
  validateId(workspaceId)
  validatePath(relativePath)
  const value = await invoke('open_workspace_editor', { workspaceId, relativePath })
  if (!isReceipt(value, workspaceId)) {
    throw new Error('Invalid editor launch receipt')
  }
  return value
}

function validateId(value: string): void {
  if (!ID_PATTERN.test(value)) throw new Error('Invalid workspace identifier')
}

function validatePath(value: string): void {
  const bytes = new TextEncoder().encode(value).length
  if (bytes > MAX_PATH_BYTES
    || value.length === 0
    || value.startsWith('/')
    || value.includes('\\')
    || Array.from(value).some(character => character.charCodeAt(0) < 0x20)
    || value.split('/').some(part => part.length === 0 || part === '.' || part === '..')) {
    throw new Error('Invalid editor file path')
  }
}

function isReceipt(value: unknown, workspaceId: string): value is EditorLaunchReceipt {
  return typeof value === 'object'
    && value !== null
    && !Array.isArray(value)
    && Object.keys(value).length === 2
    && (value as Record<string, unknown>).workspaceId === workspaceId
    && (value as Record<string, unknown>).target === 'system_default'
}
