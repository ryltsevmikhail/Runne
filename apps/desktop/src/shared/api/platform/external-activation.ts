import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import { listen as tauriListen } from '@tauri-apps/api/event'

export const EXTERNAL_ACTIVATION_EVENT = 'runne://external-activation'
export type ActivationEvent = 'approval' | 'task_completed' | 'runtime_attention'
export interface ActivationTarget {
  readonly runtime: string | null
  readonly projectId: string | null
  readonly workspaceId: string | null
  readonly taskRunId: string | null
  readonly approvalId: string | null
  readonly event: ActivationEvent | null
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
type Listen = (event: string, handler: (event: { payload: unknown }) => void) => Promise<() => void>
const ids = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const events: readonly ActivationEvent[] = ['approval', 'task_completed', 'runtime_attention']
const keys = ['runtime', 'projectId', 'workspaceId', 'taskRunId', 'approvalId', 'event'] as const

export async function loadPendingExternalActivation(invoke: Invoke = tauriInvoke): Promise<ActivationTarget | null> {
  const value = await invoke('get_pending_external_activation')
  return value === null ? null : parseActivationTarget(value)
}

export async function listenExternalActivation(
  onTarget: (target: ActivationTarget) => void,
  listen: Listen = tauriListen,
): Promise<() => void> {
  return listen(EXTERNAL_ACTIVATION_EVENT, ({ payload }) => {
    const target = parseActivationTarget(payload)
    if (target !== null) onTarget(target)
  })
}

export function parseActivationTarget(value: unknown): ActivationTarget | null {
  if (!record(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) return null
  const target = value as Record<string, unknown>
  if (!nullableText(target.runtime, 128) || !nullableId(target.projectId) || !nullableId(target.workspaceId) || !nullableId(target.taskRunId) || !nullableId(target.approvalId) || !nullableEvent(target.event)) return null
  if (target.projectId === null && target.workspaceId === null && target.taskRunId === null && target.approvalId === null) return null
  return target as unknown as ActivationTarget
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function nullableId(value: unknown): value is string | null {
  return value === null || (typeof value === 'string' && ids.test(value))
}

function nullableText(value: unknown, max: number): value is string | null {
  return value === null || (typeof value === 'string' && value.length > 0 && value.length <= max && /^[A-Za-z0-9._/-]+$/.test(value) && !value.includes('..') && !value.startsWith('/') && !value.endsWith('/'))
}

function nullableEvent(value: unknown): value is ActivationEvent | null {
  return value === null || (typeof value === 'string' && events.includes(value as ActivationEvent))
}
