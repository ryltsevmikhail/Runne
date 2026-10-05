import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraft, ManagedTaskDraftWrite } from '@/entities/task-run/api/managed-task-draft'
import type { DraftScope } from './draft-session-contract'

interface DraftWriteHost {
  current(operation: number, scope: DraftScope): boolean
  token(): string | null
  revision(): number | null
  save(scope: DraftScope, write: ManagedTaskDraftWrite): Promise<ManagedTaskDraft>
  clear(scope: DraftScope, token: string, revision: number): Promise<ManagedTaskDraft>
  invalidate(operation: number, scope: DraftScope): void
  acknowledge(draft: ManagedTaskDraft): void
  fail(error: unknown): void
}

export async function commitDraftWrite(
  host: DraftWriteHost,
  scope: DraftScope,
  token: string,
  prompt: string,
  operation: number,
): Promise<void> {
  try {
    if (!host.current(operation, scope) || host.token() !== token) return
    const revision = host.revision()
    if (revision === null || host.token() !== token) throw new ManagedTaskDraftError('unavailable')
    const result = prompt.length === 0
      ? await host.clear(scope, token, revision)
      : await host.save(scope, { scopeToken: token, expectedRevision: revision, prompt })
    if (!host.current(operation, scope)) return
    if (result.scopeToken !== token) {
      host.invalidate(operation, scope)
      throw new ManagedTaskDraftError('conflict')
    }
    if (result.revision <= revision || (prompt.length > 0 && result.prompt !== prompt)) {
      throw new ManagedTaskDraftError('unavailable')
    }
    host.acknowledge(result)
  } catch (error) {
    if (error instanceof ManagedTaskDraftError && error.code === 'scope_changed') {
      if (host.current(operation, scope)) host.invalidate(operation, scope)
      throw error
    }
    if (!host.current(operation, scope)) return
    host.fail(error)
    throw error
  }
}
