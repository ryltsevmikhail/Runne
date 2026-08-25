import { invoke as tauriInvoke } from '@tauri-apps/api/core'

export type ApprovalState = 'pending' | 'approved' | 'denied' | 'expired' | 'cancelled'
export type ApprovalDecision = 'approve' | 'deny'
export type ApprovalDecisionState = Exclude<ApprovalState, 'pending'>
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

export interface ApprovalDecisionAcknowledgement {
  readonly approvalId: string
  readonly taskRunId: string
  readonly newVersion: number
  readonly state: ApprovalDecisionState
}

type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>
const id = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const digest = /^[0-9a-f]{64}$/
const states: readonly ApprovalState[] = ['pending', 'approved', 'denied', 'expired', 'cancelled']
const decisionStates: readonly ApprovalDecisionState[] = ['approved', 'denied', 'expired', 'cancelled']
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

export async function decideApproval(
  approval: ApprovalSummary,
  decision: ApprovalDecision,
  rendererGeneration: number,
  invoke: Invoke = tauriInvoke,
): Promise<ApprovalDecisionAcknowledgement> {
  if (!isApproval(approval) || approval.state !== 'pending' || !['approve', 'deny'].includes(decision)) throw new Error('Invalid approval decision')
  if (!Number.isSafeInteger(rendererGeneration) || rendererGeneration < 0) throw new Error('Invalid renderer generation')
  const value = await invoke('respond_to_approval', {
    request: {
      approvalId: approval.approvalId,
      expectedVersion: approval.requestVersion,
      decision,
      actionDigest: approval.actionDigest,
      policyRevision: approval.policyRevision,
      rendererGeneration,
    },
  })
  if (!isDecisionAcknowledgement(value, approval)) throw new Error('Invalid approval decision response')
  return value
}

function isApproval(value: unknown): value is ApprovalSummary {
  if (!record(value) || Object.keys(value).length !== keys.length || keys.some(key => !Object.hasOwn(value, key))) return false
  const item = value as Record<string, unknown>
  return id.test(String(item.approvalId)) && id.test(String(item.taskRunId)) && nullableId(item.attemptId) && id.test(String(item.invocationId)) && display(item.action) && display(item.resource) && digest.test(String(item.actionDigest)) && positive(item.policyRevision) && positive(item.requestVersion) && Number.isSafeInteger(item.expiresAt) && Number(item.expiresAt) > 0 && display(item.riskSummary) && typeof item.state === 'string' && states.includes(item.state as ApprovalState)
}

function isDecisionAcknowledgement(value: unknown, approval: ApprovalSummary): value is ApprovalDecisionAcknowledgement {
  if (!record(value) || Object.keys(value).length !== 4 || !['approvalId', 'taskRunId', 'newVersion', 'state'].every(key => Object.hasOwn(value, key))) return false
  const item = value as Record<string, unknown>
  return item.approvalId === approval.approvalId && item.taskRunId === approval.taskRunId && typeof item.newVersion === 'number' && Number.isSafeInteger(item.newVersion) && item.newVersion > approval.requestVersion && typeof item.state === 'string' && decisionStates.includes(item.state as ApprovalDecisionState)
}

function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function positive(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value > 0 }
function display(value: unknown): value is string { return typeof value === 'string' && value.length > 0 && value.length <= 4096 && ![...value].some(character => character < ' ' || character === '\u007f') }
function nullableId(value: unknown): value is string | null { return value === null || (typeof value === 'string' && id.test(value)) }
