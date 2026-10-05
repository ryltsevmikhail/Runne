import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraft } from '@/entities/task-run/api/managed-task-draft'
import { isDraftScopeChanged } from './draft-session-contract'
import type { DraftScope } from './draft-session-contract'

interface DraftVerificationState {
  readonly operation: number
  readonly edits: number
  readonly scope: DraftScope | null
  readonly persistedPrompt: string | null
}
interface DraftVerificationHost {
  state(): DraftVerificationState
  load(scope: DraftScope): Promise<ManagedTaskDraft>
  current(operation: number, scope: DraftScope): boolean
  edits(): number
  invalidate(operation: number, scope: DraftScope): void
  setConflict(): void
  fail(error: unknown): void
}

export async function verifyDraftForSubmission(
  host: DraftVerificationHost,
  token: string,
  revision: number,
): Promise<void> {
  const { operation, edits, scope, persistedPrompt } = host.state()
  if (scope === null) throw new ManagedTaskDraftError('unavailable')
  let current: ManagedTaskDraft
  try { current = await host.load(scope) }
  catch (error) {
    if (host.current(operation, scope)) {
      if (isDraftScopeChanged(error)) host.invalidate(operation, scope)
      else host.fail(error)
    }
    throw error
  }
  if (!host.current(operation, scope)) throw new ManagedTaskDraftError('unavailable')
  if (current.scopeToken !== token) {
    host.invalidate(operation, scope)
    throw new ManagedTaskDraftError('conflict')
  }
  if (host.edits() !== edits || current.prompt !== persistedPrompt || current.revision !== revision) {
    host.setConflict()
    throw new ManagedTaskDraftError('conflict')
  }
}
