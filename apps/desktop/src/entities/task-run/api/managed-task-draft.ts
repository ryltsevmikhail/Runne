import { invoke as tauriInvoke } from '@tauri-apps/api/core'

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
export type ManagedTaskDraftPolicy = 'protected_restart' | 'memory_only' | 'unavailable'
export type ManagedTaskDraftErrorCode = 'conflict' | 'capacity' | 'scope_changed' | 'unavailable'

export interface ManagedTaskDraft {
  readonly revision: number
  readonly prompt: string | null
  readonly scopeToken: string
}
export interface ManagedTaskDraftWrite {
  readonly scopeToken: string
  readonly expectedRevision: number
  readonly prompt: string
}
export interface ManagedTaskDraftClear {
  readonly scopeToken: string
  readonly expectedRevision: number
}

export class ManagedTaskDraftError extends Error {
  constructor(readonly code: ManagedTaskDraftErrorCode) {
    super(`Managed task draft ${code}`)
    this.name = 'ManagedTaskDraftError'
  }
}

const id = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const scopeTokenPattern = /^[0-9a-f]{64}$/
export const maxManagedTaskDraftBytes = 64 * 1024

export async function loadManagedTaskDraft(projectId: string, workspaceId: string, invoke: Invoke = tauriInvoke): Promise<ManagedTaskDraft> {
  validateScope(projectId, workspaceId)
  return draft(await call(invoke, 'load_managed_task_draft', { projectId, workspaceId }))
}

export async function saveManagedTaskDraft(
  projectId: string,
  workspaceId: string,
  write: ManagedTaskDraftWrite,
  invoke: Invoke = tauriInvoke,
): Promise<ManagedTaskDraft> {
  validateScope(projectId, workspaceId)
  if (!validScopeToken(write.scopeToken) || !revision(write.expectedRevision) || !validPrompt(write.prompt)) {
    throw new ManagedTaskDraftError('unavailable')
  }
  return draft(await call(invoke, 'save_managed_task_draft', { projectId, workspaceId, ...write }))
}

export async function clearManagedTaskDraft(
  projectId: string,
  workspaceId: string,
  clear: ManagedTaskDraftClear,
  invoke: Invoke = tauriInvoke,
): Promise<ManagedTaskDraft> {
  validateScope(projectId, workspaceId)
  if (!validScopeToken(clear.scopeToken) || !revision(clear.expectedRevision)) {
    throw new ManagedTaskDraftError('unavailable')
  }
  return draft(await call(invoke, 'clear_managed_task_draft', { projectId, workspaceId, ...clear }))
}

async function call(invoke: Invoke, command: string, args: Record<string, unknown>): Promise<unknown> {
  try { return await invoke(command, args) }
  catch (error) { throw new ManagedTaskDraftError(errorCode(error)) }
}

function draft(value: unknown): ManagedTaskDraft {
  if (!record(value) || !exact(value, ['revision', 'prompt', 'scopeToken']) || !revision(value.revision)
      || !validScopeToken(value.scopeToken) || (value.prompt !== null && !validPrompt(value.prompt))) {
    throw new ManagedTaskDraftError('unavailable')
  }
  return { revision: value.revision, prompt: value.prompt, scopeToken: value.scopeToken }
}

function errorCode(error: unknown): ManagedTaskDraftErrorCode {
  const message = typeof error === 'string' ? error : record(error) ? `${String(error.code ?? '')} ${String(error.message ?? '')}` : ''
  if (message.includes('managed_task_draft_conflict')) return 'conflict'
  if (message.includes('managed_task_draft_capacity')) return 'capacity'
  if (message.includes('managed_task_draft_scope_changed')) return 'scope_changed'
  return 'unavailable'
}
function validateScope(projectId: string, workspaceId: string): void {
  if (!id.test(projectId) || !id.test(workspaceId)) throw new ManagedTaskDraftError('unavailable')
}
function validScopeToken(value: unknown): value is string { return typeof value === 'string' && scopeTokenPattern.test(value) }
function validPrompt(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && new TextEncoder().encode(value).length <= maxManagedTaskDraftBytes
}
function revision(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 }
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key))
}
