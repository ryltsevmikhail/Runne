export interface PendingRunBinding {
  readonly recoveryToken: string
  readonly projectId: string
  readonly workspaceId: string
  readonly conversationId: string
  readonly draftScopeToken?: string
  readonly draftRevision?: number
  readonly acceptedTaskRunId?: string
  readonly navigated?: boolean
}
export type PendingRunRead = { readonly status: 'none' | 'corrupt' } | { readonly status: 'pending', readonly binding: PendingRunBinding }

const id = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/
const scopeToken = /^[0-9a-f]{64}$/
const prefix = 'runne:managed-task-run:'
const drafts = new Map<string, string>()
const MAX_DRAFT_BYTES = 64 * 1024
const MAX_DRAFT_WORKSPACES = 16

export function draftFor(workspaceId: string): string { return drafts.get(workspaceId) ?? '' }
export function setDraft(workspaceId: string, prompt: string): void {
  if (new TextEncoder().encode(prompt).length > MAX_DRAFT_BYTES) return
  drafts.delete(workspaceId)
  drafts.set(workspaceId, prompt)
  while (drafts.size > MAX_DRAFT_WORKSPACES) drafts.delete(drafts.keys().next().value!)
}
export function clearDraft(workspaceId: string): void { drafts.delete(workspaceId) }

export function savePendingRun(binding: PendingRunBinding, storage: Storage = localStorage): void {
  if (!validBinding(binding)) throw new Error('Invalid pending run identity')
  storage.setItem(key(binding.workspaceId), JSON.stringify(binding))
}

export function loadPendingRun(workspaceId: string, storage: Storage = localStorage): PendingRunRead {
  const raw = storage.getItem(key(workspaceId))
  if (raw === null) return { status: 'none' }
  try {
    const value: unknown = JSON.parse(raw)
    return validBinding(value) && value.workspaceId === workspaceId
      ? { status: 'pending', binding: value }
      : { status: 'corrupt' }
  } catch { return { status: 'corrupt' } }
}

export function clearPendingRun(workspaceId: string, storage: Storage = localStorage): void {
  storage.removeItem(key(workspaceId))
}

export function samePendingRunIntent(left: PendingRunBinding, right: PendingRunBinding): boolean {
  return left.recoveryToken === right.recoveryToken && left.projectId === right.projectId
    && left.workspaceId === right.workspaceId && left.conversationId === right.conversationId
    && left.draftScopeToken === right.draftScopeToken && left.draftRevision === right.draftRevision
}

function validBinding(value: unknown): value is PendingRunBinding {
  if (!record(value)) return false
  const expected = ['recoveryToken', 'projectId', 'workspaceId', 'conversationId',
    ...(Object.hasOwn(value, 'acceptedTaskRunId') ? ['acceptedTaskRunId'] : []),
    ...(Object.hasOwn(value, 'navigated') ? ['navigated'] : []),
    ...(Object.hasOwn(value, 'draftScopeToken') ? ['draftScopeToken'] : []),
    ...(Object.hasOwn(value, 'draftRevision') ? ['draftRevision'] : [])]
  if (Object.keys(value).length !== expected.length || !expected.every(field => Object.hasOwn(value, field))) return false
  return [value.recoveryToken, value.projectId, value.workspaceId, value.conversationId]
    .every(item => typeof item === 'string' && id.test(item))
    && (Object.hasOwn(value, 'draftScopeToken') === Object.hasOwn(value, 'draftRevision'))
    && (!Object.hasOwn(value, 'draftScopeToken') || (typeof value.draftScopeToken === 'string' && scopeToken.test(value.draftScopeToken)))
    && (!Object.hasOwn(value, 'draftRevision') || (typeof value.draftRevision === 'number' && Number.isSafeInteger(value.draftRevision) && value.draftRevision >= 0))
    && (!Object.hasOwn(value, 'acceptedTaskRunId') || (typeof value.acceptedTaskRunId === 'string' && id.test(value.acceptedTaskRunId)))
    && (!Object.hasOwn(value, 'navigated') || typeof value.navigated === 'boolean')
}
function key(workspaceId: string): string { return `${prefix}${workspaceId}` }
function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
