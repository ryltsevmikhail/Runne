import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type LocalCommandOutcome = 'not_started' | 'running' | 'exited' | 'outcome_unknown'
export type LocalCommandStop = 'not_requested' | 'requested' | 'confirmed' | 'unconfirmed'
export type RemoteEffectOutcome = 'not_applicable' | 'not_started' | 'running' | 'completed' | 'failed' | 'incomplete' | 'cancelled' | 'unknown'
export type RemotePublication = 'not_applicable' | 'unknown' | 'allowed' | 'withheld'
export type RemoteAccounting = 'not_applicable' | 'unknown' | 'known'
export type RemoteCancellation = 'already_terminal' | 'not_requested' | 'requested' | 'confirmed' | 'unconfirmed' | 'unknown'
export type RemoteAvailability = 'available' | 'unavailable' | 'not_configured' | 'unknown'
export type SuccessorEligibility = 'not_applicable' | 'blocked' | 'requires_duplicate_effect_acknowledgment' | 'eligible'

export interface TaskRunEffects {
  readonly taskRunId: string
  readonly streamVersion: number
  readonly attemptId: string | null
  readonly cancellationRequested: boolean
  readonly localCommand: { readonly outcome: LocalCommandOutcome, readonly stop: LocalCommandStop, readonly exitCode: number | null } | null
  readonly remote: {
    readonly outcome: RemoteEffectOutcome
    readonly publication: RemotePublication
    readonly accounting: RemoteAccounting
    readonly cancellation: RemoteCancellation
    readonly availability: RemoteAvailability
    readonly capabilities: { readonly statusCheck: boolean, readonly streamResume: boolean, readonly remoteCancel: boolean }
    readonly usageKnown: boolean | null
  }
  readonly successor: SuccessorEligibility
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const canonicalId = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const localOutcomes = ['not_started', 'running', 'exited', 'outcome_unknown'] as const
const localStops = ['not_requested', 'requested', 'confirmed', 'unconfirmed'] as const
const remoteOutcomes = ['not_applicable', 'not_started', 'running', 'completed', 'failed', 'incomplete', 'cancelled', 'unknown'] as const
const publications = ['not_applicable', 'unknown', 'allowed', 'withheld'] as const
const accounting = ['not_applicable', 'unknown', 'known'] as const
const cancellations = ['already_terminal', 'not_requested', 'requested', 'confirmed', 'unconfirmed', 'unknown'] as const
const availabilities = ['available', 'unavailable', 'not_configured', 'unknown'] as const
const successors = ['not_applicable', 'blocked', 'requires_duplicate_effect_acknowledgment', 'eligible'] as const

export async function getTaskRunEffects(taskRunId: string, invoke: Invoke = tauriInvoke): Promise<TaskRunEffects> {
  if (!canonicalId.test(taskRunId)) throw new Error('Invalid TaskRun identity')
  const value = await invoke('get_task_run_effects', { taskRunId })
  if (!isEffects(value, taskRunId)) throw new Error('Invalid TaskRun effects response')
  return value
}

export function isTaskRunEffects(value: unknown, taskRunId: string): value is TaskRunEffects {
  return isEffects(value, taskRunId)
}

function isEffects(value: unknown, taskRunId: string): value is TaskRunEffects {
  if (!record(value, ['taskRunId', 'streamVersion', 'attemptId', 'cancellationRequested', 'localCommand', 'remote', 'successor'])
      || value.taskRunId !== taskRunId || !canonicalId.test(String(value.taskRunId))
      || !positiveInteger(value.streamVersion) || !nullableId(value.attemptId)
      || typeof value.cancellationRequested !== 'boolean' || !member(value.successor, successors)) return false
  const local = value.localCommand
  if (local !== null && (!record(local, ['outcome', 'stop', 'exitCode'])
      || !member(local.outcome, localOutcomes) || !member(local.stop, localStops)
      || !(local.exitCode === null || signedI32(local.exitCode))
      || (local.outcome === 'running' && local.stop === 'confirmed')
      || ((local.outcome === 'exited') !== (local.exitCode !== null)))) return false
  const remote = value.remote
  if (!record(remote, ['outcome', 'publication', 'accounting', 'cancellation', 'availability', 'capabilities', 'usageKnown'])
      || !member(remote.outcome, remoteOutcomes) || !member(remote.cancellation, cancellations)
      || !member(remote.publication, publications) || !member(remote.accounting, accounting)
      || !member(remote.availability, availabilities)
      || !(remote.usageKnown === null || typeof remote.usageKnown === 'boolean')
      || !record(remote.capabilities, ['statusCheck', 'streamResume', 'remoteCancel'])
      || typeof remote.capabilities.statusCheck !== 'boolean'
      || typeof remote.capabilities.streamResume !== 'boolean'
      || typeof remote.capabilities.remoteCancel !== 'boolean') return false
  if (remote.cancellation === 'already_terminal' && (!value.cancellationRequested || remote.outcome !== 'completed')) return false
  if (remote.cancellation === 'confirmed' && remote.outcome !== 'cancelled') return false
  if (remote.outcome === 'not_applicable'
      && (remote.publication !== 'not_applicable' || remote.accounting !== 'not_applicable')) return false
  if (remote.publication === 'withheld' && remote.outcome === 'unknown') return false
  return true
}

function nullableId(value: unknown): boolean { return value === null || (typeof value === 'string' && canonicalId.test(value)) }
function positiveInteger(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 }
function signedI32(value: unknown): value is number { return typeof value === 'number' && Number.isInteger(value) && value >= -2147483648 && value <= 2147483647 }
function member<const T extends readonly string[]>(value: unknown, options: T): value is T[number] { return typeof value === 'string' && options.includes(value) }
function record<const K extends string>(value: unknown, keys: readonly K[]): value is Record<K, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key)) }
