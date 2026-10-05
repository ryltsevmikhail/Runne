import { invoke as tauriInvoke } from '@tauri-apps/api/core'
import type { ManagedTaskDraftPolicy } from './managed-task-draft'

type UnavailableProjection = { readonly status: 'unavailable', readonly reason: 'runtime_projection_missing' }
export interface EffectiveTaskAuthority {
  readonly provider: UnavailableProjection
  readonly model: UnavailableProjection
  readonly policy: UnavailableProjection
}
export interface ManagedTaskRunPreflight {
  readonly status: 'ready' | 'unavailable'
  readonly generation: number | null
  readonly projectId: string
  readonly workspaceId: string
  readonly conversationId: string | null
  readonly canStart: boolean
  readonly startUnavailableReason: string | null
  readonly authority: EffectiveTaskAuthority
  readonly draftPolicy: ManagedTaskDraftPolicy
  readonly recoveryToken: string | null
}
export type ManagedTaskRunAck =
  | { readonly status: 'accepted', readonly taskRunId: string, readonly streamVersion: 2, readonly recoveryToken: string }
  | { readonly status: 'uncertain', readonly taskRunId: string | null, readonly streamVersion: number | null, readonly recoveryToken: string }
export type ManagedTaskRunRecovery =
  | { readonly status: 'accepted', readonly taskRunId: string, readonly streamVersion: 2, readonly workspaceId: string, readonly conversationId: string }
  | { readonly status: 'not_committed' | 'uncertain' | 'unavailable', readonly taskRunId: string | null, readonly streamVersion: number | null, readonly workspaceId: null, readonly conversationId: null }
export interface ManagedTaskRunSummary {
  readonly taskRunId: string
  readonly workspaceId: string | null
  readonly conversationId: string | null
  readonly state: string
  readonly terminal: ManagedTaskRunTerminal | null
  readonly streamVersion: number
  readonly activeAttemptId: string | null
}
export type ManagedTaskRunTerminal = 'success' | 'failure' | 'cancelled' | 'budget_exhausted' | 'policy_denied' | 'unrecoverable'
export type ManagedTaskRunsSnapshot =
  | { readonly status: 'available', readonly taskRuns: readonly ManagedTaskRunSummary[] }
  | { readonly status: 'unavailable', readonly taskRuns: readonly [] }
export interface ManagedAttentionItem {
  readonly approvalId: string | null
  readonly taskRunId: string | null
  readonly kind: 'approval' | 'failed' | 'uncertain' | 'effective_authority_unavailable' | 'runtime_unavailable' | 'effects_unavailable'
  readonly workspaceId: string | null
  readonly conversationId: string | null
}
export type ManagedAttentionSnapshot =
  | { readonly status: 'available', readonly complete: boolean, readonly items: readonly ManagedAttentionItem[] }
  | { readonly status: 'unavailable', readonly complete: false, readonly items: readonly [] }

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const id = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const taskStates = ['created', 'queued', 'admitted', 'running', 'waiting', 'retrying', 'checkpointing', 'cancelling', 'reconciling', 'succeeded', 'failed', 'cancelled', 'budget_exhausted', 'policy_denied', 'unrecoverable'] as const
const startReasons = ['runtime_unavailable', 'submit_capability_missing', 'stale_generation', 'workspace_scope_invalid', 'conversation_unavailable', 'mutation_authority_unavailable'] as const
const MAX_TASK_RUNS = 256
const MAX_ATTENTION_ITEMS = 64

export async function prepareManagedTaskRun(projectId: string, workspaceId: string, invoke: Invoke = tauriInvoke): Promise<ManagedTaskRunPreflight> {
  validateId(projectId); validateId(workspaceId)
  const value = await invoke('prepare_managed_task_run', { projectId, workspaceId })
  if (!isPreflight(value) || value.projectId !== projectId || value.workspaceId !== workspaceId) throw new Error('Invalid managed TaskRun preflight')
  return value
}

export async function startManagedTaskRun(request: {
  readonly workspaceId: string, readonly conversationId: string, readonly prompt: string,
  readonly generation: number, readonly recoveryToken: string,
}, invoke: Invoke = tauriInvoke): Promise<ManagedTaskRunAck> {
  validateId(request.workspaceId); validateId(request.conversationId); validateId(request.recoveryToken)
  if (!Number.isSafeInteger(request.generation) || request.generation < 1 || request.prompt.trim().length === 0
      || new TextEncoder().encode(request.prompt).length > 64 * 1024) throw new Error('Invalid managed TaskRun request')
  const value = await invoke('start_managed_task_run', request)
  if (!isAck(value) || value.recoveryToken !== request.recoveryToken) throw new Error('Invalid managed TaskRun acknowledgement')
  return value
}

export async function recoverManagedTaskRun(recoveryToken: string, invoke: Invoke = tauriInvoke): Promise<ManagedTaskRunRecovery> {
  validateId(recoveryToken)
  const value = await invoke('recover_managed_task_run', { recoveryToken })
  if (!isRecovery(value)) throw new Error('Invalid managed TaskRun recovery response')
  return value
}

export async function listManagedTaskRuns(invoke: Invoke = tauriInvoke): Promise<ManagedTaskRunsSnapshot> {
  const value = await invoke('list_managed_task_runs')
  if (!isTaskRunsSnapshot(value)) throw new Error('Invalid managed TaskRun inventory')
  return value
}

export async function getManagedAttentionSnapshot(invoke: Invoke = tauriInvoke): Promise<ManagedAttentionSnapshot> {
  const value = await invoke('get_managed_attention_snapshot')
  if (!isAttentionSnapshot(value)) throw new Error('Invalid managed attention snapshot')
  return value
}

function isPreflight(value: unknown): value is ManagedTaskRunPreflight {
  if (!record(value) || !exact(value, ['status', 'generation', 'projectId', 'workspaceId', 'conversationId', 'canStart', 'startUnavailableReason', 'authority', 'draftPolicy', 'recoveryToken'])) return false
  const ready = value.status === 'ready' && value.canStart === true && value.startUnavailableReason === null
    && positive(value.generation) && id.test(String(value.conversationId)) && id.test(String(value.recoveryToken))
  const unavailable = value.status === 'unavailable' && value.canStart === false
    && (value.startUnavailableReason === null || (typeof value.startUnavailableReason === 'string' && startReasons.includes(value.startUnavailableReason as typeof startReasons[number])))
    && (value.generation === null || positive(value.generation)) && value.conversationId === null && value.recoveryToken === null
  return (ready || unavailable) && id.test(String(value.projectId)) && id.test(String(value.workspaceId))
    && isEffectiveAuthority(value.authority)
    && ['protected_restart', 'memory_only', 'unavailable'].includes(String(value.draftPolicy))
}
function isAck(value: unknown): value is ManagedTaskRunAck {
  if (!record(value) || !exact(value, ['status', 'taskRunId', 'streamVersion', 'recoveryToken']) || !id.test(String(value.recoveryToken))) return false
  if (value.status === 'accepted') return id.test(String(value.taskRunId)) && value.streamVersion === 2
  return value.status === 'uncertain' && nullableId(value.taskRunId) && (value.streamVersion === null || positive(value.streamVersion))
}
function isRecovery(value: unknown): value is ManagedTaskRunRecovery {
  if (!record(value)) return false
  if (value.status === 'accepted') return exact(value, ['status', 'taskRunId', 'streamVersion', 'workspaceId', 'conversationId'])
    && id.test(String(value.taskRunId)) && value.streamVersion === 2 && id.test(String(value.workspaceId)) && id.test(String(value.conversationId))
  return ['not_committed', 'uncertain', 'unavailable'].includes(String(value.status))
    && exact(value, ['status', 'taskRunId', 'streamVersion', 'workspaceId', 'conversationId'])
    && nullableId(value.taskRunId) && (value.streamVersion === null || positive(value.streamVersion))
    && value.workspaceId === null && value.conversationId === null
}
function isTaskRunsSnapshot(value: unknown): value is ManagedTaskRunsSnapshot {
  if (!record(value) || !exact(value, ['status', 'taskRuns']) || !Array.isArray(value.taskRuns) || value.taskRuns.length > MAX_TASK_RUNS) return false
  if (value.status === 'unavailable') return value.taskRuns.length === 0
  return value.status === 'available' && value.taskRuns.every(isTaskRunSummary)
    && new Set(value.taskRuns.map((item: ManagedTaskRunSummary) => item.taskRunId)).size === value.taskRuns.length
}
function isTaskRunSummary(value: unknown): value is ManagedTaskRunSummary {
  return record(value) && exact(value, ['taskRunId', 'workspaceId', 'conversationId', 'state', 'terminal', 'streamVersion', 'activeAttemptId'])
    && id.test(String(value.taskRunId)) && nullableId(value.workspaceId) && nullableId(value.conversationId)
    && typeof value.state === 'string' && taskStates.includes(value.state as typeof taskStates[number])
    && (value.terminal === null || ['success', 'failure', 'cancelled', 'budget_exhausted', 'policy_denied', 'unrecoverable'].includes(String(value.terminal)))
    && positive(value.streamVersion) && nullableId(value.activeAttemptId)
}
function isAttentionSnapshot(value: unknown): value is ManagedAttentionSnapshot {
  if (!record(value) || !exact(value, ['status', 'complete', 'items']) || !Array.isArray(value.items) || value.items.length > MAX_ATTENTION_ITEMS || typeof value.complete !== 'boolean') return false
  if (value.status === 'unavailable') return value.complete === false && value.items.length === 0
  return value.status === 'available' && value.items.every(isAttentionItem)
}
function isAttentionItem(value: unknown): value is ManagedAttentionItem {
  if (!record(value) || !exact(value, ['approvalId', 'taskRunId', 'kind', 'workspaceId', 'conversationId'])
      || !nullableId(value.approvalId) || !nullableId(value.taskRunId) || !nullableId(value.workspaceId) || !nullableId(value.conversationId)) return false
  if (value.kind === 'approval') return value.approvalId !== null && value.taskRunId !== null && value.workspaceId === null && value.conversationId === null
  if (value.kind === 'failed' || value.kind === 'uncertain') return value.approvalId === null && value.taskRunId !== null
  return ['effective_authority_unavailable', 'runtime_unavailable', 'effects_unavailable'].includes(String(value.kind))
    && value.approvalId === null && value.taskRunId === null && value.workspaceId === null && value.conversationId === null
}
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function exact(value: Record<string, unknown>, keys: readonly string[]): boolean { return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)) }
function positive(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 }
function nullableId(value: unknown): boolean { return value === null || (typeof value === 'string' && id.test(value)) }
function validateId(value: string): void { if (!id.test(value)) throw new Error('Invalid canonical identifier') }
function isUnavailableProjection(value: unknown): value is UnavailableProjection {
  return record(value) && exact(value, ['status', 'reason'])
    && value.status === 'unavailable' && value.reason === 'runtime_projection_missing'
}
function isEffectiveAuthority(value: unknown): value is EffectiveTaskAuthority {
  return record(value) && exact(value, ['provider', 'model', 'policy'])
    && isUnavailableProjection(value.provider) && isUnavailableProjection(value.model) && isUnavailableProjection(value.policy)
}
