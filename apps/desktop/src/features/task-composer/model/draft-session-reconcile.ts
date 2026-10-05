import type { ManagedTaskDraft } from '@/entities/task-run/api/managed-task-draft'
import { isDraftScopeChanged } from './draft-session-contract'
import type { DraftSaveStatus, DraftScope, SubmittedDraft } from './draft-session-contract'

interface DraftReconcileState {
  readonly operation: number
  readonly edits: number
  readonly scope: DraftScope | null
  readonly scopeToken: string | null
  readonly status: DraftSaveStatus
  readonly prompt: string
}
interface DraftReconcileHost {
  state(): DraftReconcileState
  load(scope: DraftScope): Promise<ManagedTaskDraft>
  current(operation: number, scope: DraftScope): boolean
  invalidate(operation: number, scope: DraftScope): void
  adopt(draft: ManagedTaskDraft, prompt?: string): void
  flush(): Promise<SubmittedDraft | null>
  fail(error: unknown): void
}

export async function reconcileDraftConflict(
  host: DraftReconcileHost,
  choice: 'keep_local' | 'use_saved',
): Promise<void> {
  const { scope, operation, edits, scopeToken, status, prompt } = host.state()
  if (scope === null || scopeToken === null || status !== 'conflict') return
  try {
    const current = await host.load(scope)
    if (!host.current(operation, scope)) return
    if (current.scopeToken !== scopeToken) { host.invalidate(operation, scope); return }
    if (host.state().edits !== edits) return
    host.adopt(current, choice === 'keep_local' ? prompt : current.prompt ?? '')
    if (choice === 'keep_local') await host.flush()
  } catch (error) {
    if (host.current(operation, scope)) {
      if (isDraftScopeChanged(error)) host.invalidate(operation, scope)
      else host.fail(error)
    }
  }
}
