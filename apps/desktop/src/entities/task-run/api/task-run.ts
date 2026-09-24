import { Channel, invoke as tauriInvoke } from '@tauri-apps/api/core'

export type TaskRunRecovery = 'live' | 'reconnecting' | 'incompatible' | 'revoked' | 'resync_required' | 'fatal'
export type TaskRunTerminal = 'success' | 'failure' | 'cancelled' | 'budget_exhausted' | 'policy_denied' | 'unrecoverable'
export type TaskRunState = 'created' | 'queued' | 'admitted' | 'running' | 'waiting' | 'retrying' | 'checkpointing' | 'cancelling' | 'reconciling' | 'succeeded' | 'failed' | 'cancelled' | 'budget_exhausted' | 'policy_denied' | 'unrecoverable'
export type TaskRunTimelineKind = 'created' | 'queued' | 'admitted' | 'attempt_started' | 'wait_started' | 'resumed' | 'retrying' | 'checkpoint_started' | 'checkpoint_committed' | 'cancellation_requested' | 'cancellation_completed' | 'cancelled' | 'completed' | 'failed' | 'budget_exhausted' | 'policy_denied' | 'reconciliation_started' | 'reconciliation_completed' | 'unrecoverable' | 'cycle_started' | 'context_committed' | 'plan_committed' | 'step_outcome_recorded' | 'cycle_completed' | 'next_cycle_created' | 'retry_scheduled' | 'retry_attempt_activated' | 'recovery_resume_started' | 'loop_checkpoint_started' | 'loop_checkpoint_recorded' | 'loop_checkpoint_committed' | 'loop_wake_accepted'
export interface TaskRunTimelineEntry { readonly eventId: string, readonly sequence: number, readonly committedAt: number, readonly kind: TaskRunTimelineKind, readonly attemptId: string | null }
export interface TaskRunTimeline { readonly taskRunId: string, readonly projectionRevision: number, readonly streamVersion: number, readonly state: TaskRunState, readonly activeAttemptId: string | null, readonly terminal: TaskRunTerminal | null, readonly entries: readonly TaskRunTimelineEntry[], readonly recovery: TaskRunRecovery }
export interface TaskRunSession { readonly resync: () => Promise<TaskRunTimeline>, readonly unsubscribe: () => Promise<void> }
export interface TaskRunCancellation { readonly taskRunId: string, readonly streamVersion: number }
export interface TaskRunSubmission { readonly taskRunId: string, readonly streamVersion: 2 }

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
type Update = { readonly kind: 'update', readonly taskRunId: string, readonly projectionRevision: number, readonly streamVersion: number, readonly entry: TaskRunTimelineEntry | null, readonly recovery: TaskRunRecovery }
type TaskRunErrorCode = 'task_run_subscription_unavailable' | 'runtime_incompatible' | 'runtime_revoked' | 'replay_resync_required' | 'runtime_identity_conflict' | 'local_projection_unavailable'
const canonicalId = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const recoveries = ['live', 'reconnecting', 'incompatible', 'revoked', 'resync_required', 'fatal'] as const
const terminals = ['success', 'failure', 'cancelled', 'budget_exhausted', 'policy_denied', 'unrecoverable'] as const
const states = ['created', 'queued', 'admitted', 'running', 'waiting', 'retrying', 'checkpointing', 'cancelling', 'reconciling', 'succeeded', 'failed', 'cancelled', 'budget_exhausted', 'policy_denied', 'unrecoverable'] as const
const kinds = ['created', 'queued', 'admitted', 'attempt_started', 'wait_started', 'resumed', 'retrying', 'checkpoint_started', 'checkpoint_committed', 'cancellation_requested', 'cancellation_completed', 'cancelled', 'completed', 'failed', 'budget_exhausted', 'policy_denied', 'reconciliation_started', 'reconciliation_completed', 'unrecoverable', 'cycle_started', 'context_committed', 'plan_committed', 'step_outcome_recorded', 'cycle_completed', 'next_cycle_created', 'retry_scheduled', 'retry_attempt_activated', 'recovery_resume_started', 'loop_checkpoint_started', 'loop_checkpoint_recorded', 'loop_checkpoint_committed', 'loop_wake_accepted'] as const
const errorCodes = ['task_run_subscription_unavailable', 'runtime_incompatible', 'runtime_revoked', 'replay_resync_required', 'runtime_identity_conflict', 'local_projection_unavailable'] as const

export async function getTaskRunTimeline(taskRunId: string, invoke: Invoke = tauriInvoke): Promise<TaskRunTimeline> {
  validateId(taskRunId)
  const value = await invoke('get_task_run_timeline', { taskRunId })
  if (!isTimeline(value, taskRunId)) throw new Error('Invalid TaskRun response')
  return value
}

export async function cancelTaskRun(taskRunId: string, expectedVersion: number, invoke: Invoke = tauriInvoke): Promise<TaskRunCancellation> {
  validateId(taskRunId)
  if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) throw new Error('Invalid TaskRun version')
  const value = await invoke('cancel_task_run', { taskRunId, expectedVersion })
  const response = value as { taskRunId?: unknown, streamVersion?: unknown }
  if (!record(value, ['taskRunId', 'streamVersion']) || response.taskRunId !== taskRunId || typeof response.streamVersion !== 'number' || !integer(response.streamVersion) || response.streamVersion <= expectedVersion) throw new Error('Invalid TaskRun cancellation response')
  return response as TaskRunCancellation
}

export async function submitTaskRun(conversationId: string, workspaceId: string, prompt: string, invoke: Invoke = tauriInvoke): Promise<TaskRunSubmission> {
  validateId(conversationId)
  validateId(workspaceId)
  if (prompt.trim().length === 0 || new TextEncoder().encode(prompt).length > 64 * 1024) throw new Error('Invalid TaskRun prompt')
  const value = await invoke('submit_task_run', { conversationId, workspaceId, prompt })
  const response = value as { taskRunId?: unknown, streamVersion?: unknown }
  if (!record(value, ['taskRunId', 'streamVersion']) || typeof response.taskRunId !== 'string' || !canonicalId.test(response.taskRunId) || response.streamVersion !== 2) throw new Error('Invalid TaskRun submission response')
  return response as TaskRunSubmission
}

export async function subscribeTaskRunTimeline(taskRunId: string, initial: TaskRunTimeline, onTimeline: (value: TaskRunTimeline) => void, invoke: Invoke = tauriInvoke): Promise<TaskRunSession> {
  validateId(taskRunId)
  if (!isTimeline(initial, taskRunId)) throw new Error('Invalid TaskRun response')
  let snapshot = initial
  let subscriptionId: string | null = null
  let closed = false
  let terminal = false
  let failure: unknown = null
  let installed = false
  let pending: unknown[] = []
  let processing = Promise.resolve()
  const close = (error: unknown): void => {
    if (failure !== null) return
    failure = error
    closed = true
    terminal = true
    installed = false
    pending = []
    subscriptionId = null
    if (snapshot.recovery === 'live') snapshot = { ...snapshot, recovery: 'reconnecting' }
    onTimeline(snapshot)
  }
  const serialize = (operation: () => Promise<void>): Promise<void> => (processing = processing.then(operation, operation).catch(close))
  const stop = async (): Promise<void> => {
    const current = subscriptionId
    subscriptionId = null
    if (current !== null) await invoke('cancel_task_run_subscription', { subscriptionId: current })
  }
  const apply = async (value: unknown): Promise<void> => {
      if (closed || terminal) return
      const update = parseUpdate(value, taskRunId)
      if (update === null) {
        const current = subscriptionId
        close(new Error('Invalid TaskRun delivery'))
        if (current !== null) {
          try { await invoke('cancel_task_run_subscription', { subscriptionId: current }) }
          catch { /* Best-effort cancellation follows the terminal failure. */ }
        }
        return
      }
      if (update.kind === 'error') {
        terminal = true
        installed = false
        pending = []
        subscriptionId = null
        snapshot = { ...snapshot, recovery: recoveryFor(update.code) }
        onTimeline(snapshot)
        return
      }
      if (update.projectionRevision <= snapshot.projectionRevision) return
      if (update.projectionRevision !== snapshot.projectionRevision + 1 || update.streamVersion < snapshot.streamVersion) {
        try { snapshot = await getTaskRunTimeline(taskRunId, invoke); onTimeline(snapshot); await stop(); if (!closed && snapshot.recovery === 'live') await start() } catch (error) { close(error) }; return
      }
      snapshot = { ...snapshot, projectionRevision: update.projectionRevision, streamVersion: update.streamVersion, entries: update.entry === null ? snapshot.entries : [...snapshot.entries, update.entry], recovery: update.recovery }
      onTimeline(snapshot)
      if (subscriptionId !== null) await invoke('ack_task_run_update', { subscriptionId, projectionRevision: update.projectionRevision })
  }
  const receive = (value: unknown): void => {
    if (closed || terminal) return
    if (!installed) { pending.push(value); return }
    void serialize(() => apply(value))
  }
  const start = async (): Promise<void> => {
    const channel = new Channel<unknown>(receive)
    const value = await invoke('subscribe_task_run_timeline', { taskRunId, onUpdate: channel })
    if (typeof value !== 'string' || !canonicalId.test(value)) throw new Error('Invalid TaskRun subscription response')
    if (closed) { await invoke('cancel_task_run_subscription', { subscriptionId: value }); return }
    subscriptionId = value
    installed = true
    const buffered = pending
    pending = []
    for (const delivery of buffered) await serialize(() => apply(delivery))
  }
  if (snapshot.recovery === 'live') {
    try { await start() }
    catch (error) { closed = true; installed = false; pending = []; throw error }
  }
  return {
    resync: async () => { if (failure !== null) throw failure; if (closed || snapshot.recovery !== 'resync_required') throw new Error('TaskRun resync is not required'); snapshot = await invokeTimeline('resync_task_run_timeline', taskRunId, invoke); onTimeline(snapshot); return snapshot },
    unsubscribe: async () => { if (failure !== null) throw failure; closed = true; installed = false; pending = []; try { await stop() } catch (error) { close(error); throw error } },
  }
}

async function invokeTimeline(command: string, taskRunId: string, invoke: Invoke): Promise<TaskRunTimeline> { const value = await invoke(command, { taskRunId }); if (!isTimeline(value, taskRunId)) throw new Error('Invalid TaskRun response'); return value }
function validateId(value: string): void { if (!canonicalId.test(value)) throw new Error('Invalid TaskRun identity') }
function isTimeline(value: unknown, taskRunId: string): value is TaskRunTimeline { return record(value, ['taskRunId', 'projectionRevision', 'streamVersion', 'state', 'activeAttemptId', 'terminal', 'entries', 'recovery']) && value.taskRunId === taskRunId && integer(value.projectionRevision) && integer(value.streamVersion) && stringIn(value.state, states) && nullableId(value.activeAttemptId) && nullableIn(value.terminal, terminals) && Array.isArray(value.entries) && value.entries.every(isEntry) && stringIn(value.recovery, recoveries) }
function isEntry(value: unknown): value is TaskRunTimelineEntry { return record(value, ['eventId', 'sequence', 'committedAt', 'kind', 'attemptId']) && canonicalId.test(String(value.eventId)) && integer(value.sequence) && integer(value.committedAt) && stringIn(value.kind, kinds) && nullableId(value.attemptId) }
function parseUpdate(value: unknown, taskRunId: string): Update | { kind: 'error', code: TaskRunErrorCode } | null {
  if (record(value, ['kind', 'code'])) return value.kind === 'error' && stringIn(value.code, errorCodes) ? { kind: 'error', code: value.code } : null
  if (!record(value, ['kind', 'taskRunId', 'projectionRevision', 'streamVersion', 'entry', 'recovery'])) return null
  return value.kind === 'update' && value.taskRunId === taskRunId && integer(value.projectionRevision) && integer(value.streamVersion) && (value.entry === null || isEntry(value.entry)) && stringIn(value.recovery, recoveries) ? value as Update : null
}
function recoveryFor(code: TaskRunErrorCode): TaskRunRecovery { return code === 'runtime_revoked' ? 'revoked' : code === 'replay_resync_required' ? 'resync_required' : code === 'runtime_incompatible' ? 'incompatible' : code === 'runtime_identity_conflict' || code === 'local_projection_unavailable' ? 'fatal' : 'reconnecting' }
function nullableId(value: unknown): boolean { return value === null || (typeof value === 'string' && canonicalId.test(value)) }
function nullableIn<T extends string>(value: unknown, values: readonly T[]): boolean { return value === null || stringIn(value, values) }
function stringIn<T extends string>(value: unknown, values: readonly T[]): value is T { return typeof value === 'string' && (values as readonly string[]).includes(value) }
function integer(value: unknown): boolean { return Number.isSafeInteger(value) }
function record<const K extends string>(value: unknown, keys: readonly K[]): value is Record<K, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)) }
