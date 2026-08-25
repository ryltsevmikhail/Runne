import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired' | 'cancelled'
export interface ApprovalSummary {
  readonly approvalId: string
  readonly taskRunId: string
  readonly attemptId: string | null
  readonly invocationId: string
  readonly action: string
  readonly resource: string
  readonly actionDigest: string
  readonly policyRevision: number
  readonly requestVersion: number
  readonly expiresAt: number
  readonly riskSummary: string
  readonly state: ApprovalState
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const id = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digest = /^[0-9a-f]{64}$/
const states: readonly ApprovalState[] = ['pending', 'approved', 'denied', 'expired', 'cancelled']
const keys = ['approvalId', 'taskRunId', 'attemptId', 'invocationId', 'action', 'resource', 'actionDigest', 'policyRevision', 'requestVersion', 'expiresAt', 'riskSummary', 'state'] as const

export async function listPendingApprovals(invoke: Invoke = tauriInvoke): Promise<readonly ApprovalSummary[]> {
  const value = await invoke('list_pending_approvals')
  if (!Array.isArray(value) || !value.every(isApproval)) throw new Error('Invalid approval response')
  return value
}

export async function getApproval(approvalId: string, invoke: Invoke = tauriInvoke): Promise<ApprovalSummary> {
  if (!id.test(approvalId)) throw new Error('Invalid approval identity')
  const value = await invoke('get_approval', { approvalId })
  if (!isApproval(value) || value.approvalId !== approvalId) throw new Error('Invalid approval response')
  return value
}

function isApproval(value: unknown): value is ApprovalSummary {
  if (!record(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) return false
  const item = value as Record<string, unknown>
  return id.test(String(item.approvalId)) && id.test(String(item.taskRunId)) && nullableId(item.attemptId) && id.test(String(item.invocationId)) && display(item.action) && display(item.resource) && digest.test(String(item.actionDigest)) && positive(item.policyRevision) && positive(item.requestVersion) && Number.isSafeInteger(item.expiresAt) && Number(item.expiresAt) > 0 && display(item.riskSummary) && typeof item.state === 'string' && states.includes(item.state as ApprovalState)
}

function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function positive(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 }
function display(value: unknown): value is string { return typeof value === 'string' && value.length > 0 && value.length <= 4096 && ![...value].some(character => character < ' ' || character === '\u007f') }
function nullableId(value: unknown): value is string | null { return value === null || (typeof value === 'string' && id.test(value)) }
