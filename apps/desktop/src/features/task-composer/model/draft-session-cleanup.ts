import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraft, ManagedTaskDraftPolicy } from '@/entities/task-run/api/managed-task-draft'
import { isDraftScopeChanged } from './draft-session-contract'
import type { DraftScope, SubmittedDraft } from './draft-session-contract'

interface DraftCleanupState {
  readonly operation: number
  readonly edits: number
  readonly scope: DraftScope | null
  readonly scopeToken: string | null
  readonly policy: ManagedTaskDraftPolicy | 'unknown'
  readonly prompt: string
  readonly persistedPrompt: string | null
}

interface DraftCleanupHost {
  state(): DraftCleanupState
  flush(): Promise<SubmittedDraft | null>
  enqueue(action: () => Promise<void>): Promise<void>
  load(scope: DraftScope): Promise<ManagedTaskDraft>
  clear(scope: DraftScope, submitted: SubmittedDraft): Promise<ManagedTaskDraft>
  current(operation: number, scope: DraftScope): boolean
  invalidate(operation: number, scope: DraftScope): void
  install(scope: DraftScope, draft: ManagedTaskDraft, operation: number): boolean
  fail(error: unknown): void
}

export class DraftSessionCleanup {
  constructor(private readonly host: DraftCleanupHost) {}

  async clearSubmitted(scope: DraftScope, submitted: SubmittedDraft): Promise<'cleared' | 'newer' | 'blocked'> {
    const operation = this.host.state().operation
    const state = this.host.state()
    if (state.scope !== null && state.scopeToken === submitted.scopeToken && state.policy === 'protected_restart') {
      try { await this.host.flush() } catch {
        const latest = this.host.state()
        if (latest.prompt !== (latest.persistedPrompt ?? '')) return 'blocked'
      }
    }
    if (!this.host.current(operation, scope)) return 'blocked'
    let outcome: 'cleared' | 'newer' | 'blocked' = 'blocked'
    await this.host.enqueue(async () => {
      if (!this.host.current(operation, scope)) return
      try {
        const cleared = await this.host.clear(scope, submitted)
        if (!this.host.current(operation, scope)) return
        if (cleared.scopeToken !== submitted.scopeToken || cleared.revision <= submitted.revision || cleared.prompt !== null) return
        if (!this.host.install(scope, cleared, operation)) return
        outcome = 'cleared'
      } catch (error) {
        if (!this.host.current(operation, scope)) return
        if (isDraftScopeChanged(error)) {
          this.host.invalidate(operation, scope)
          return
        }
        if (!(error instanceof ManagedTaskDraftError) || error.code !== 'conflict') {
          this.host.fail(error)
          return
        }
        outcome = await this.reconcile(scope, submitted, operation)
      }
    })
    return outcome
  }

  private async reconcile(scope: DraftScope, submitted: SubmittedDraft, operation: number): Promise<'cleared' | 'newer' | 'blocked'> {
    const beforeLoad = this.host.state()
    const edits = beforeLoad.edits
    const tokenBeforeLoad = beforeLoad.scopeToken
    try {
      const current = await this.host.load(scope)
      if (!this.host.current(operation, scope)) return 'blocked'
      if (current.scopeToken !== submitted.scopeToken) {
        if (tokenBeforeLoad === submitted.scopeToken) this.host.invalidate(operation, scope)
        return 'blocked'
      }
      if (this.host.state().edits !== edits || current.revision <= submitted.revision) return 'blocked'
      if (!this.host.install(scope, current, operation)) return 'blocked'
      return current.prompt === null ? 'cleared' : 'newer'
    } catch (error) {
      const state = this.host.state()
      if (this.host.current(operation, scope) && state.edits === edits) {
        if (isDraftScopeChanged(error)) this.host.invalidate(operation, scope)
        else this.host.fail(error)
      }
      return 'blocked'
    }
  }
}
