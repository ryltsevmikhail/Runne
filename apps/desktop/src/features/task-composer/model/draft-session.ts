import { reactive } from 'vue'
import { ManagedTaskDraftError, maxManagedTaskDraftBytes } from '@/entities/task-run/api/managed-task-draft'
import type {
  ManagedTaskDraft, ManagedTaskDraftPolicy,
} from '@/entities/task-run/api/managed-task-draft'
import { defaultDraftApi, emptyDraftSessionView } from './draft-session-contract'
import { isDraftScopeChanged } from './draft-session-contract'
import type { DraftApi, DraftScope, SubmittedDraft } from './draft-session-contract'
import { DraftSessionCleanup } from './draft-session-cleanup'
import { reconcileDraftConflict } from './draft-session-reconcile'
import { commitDraftWrite } from './draft-session-write'
import { verifyDraftForSubmission } from './draft-session-verify'
export type { DraftApi, DraftSaveStatus, DraftScope, SubmittedDraft } from './draft-session-contract'

export class DraftSession {
  readonly view = reactive(emptyDraftSessionView())
  private scope: DraftScope | null = null
  private operation = 0
  private edits = 0
  private persistedPrompt: string | null = null
  private timer: ReturnType<typeof setTimeout> | null = null
  private queue: Promise<void> = Promise.resolve()
  private drain: Promise<void> | null = null
  private cleanup: DraftSessionCleanup

  constructor(
    private readonly api: DraftApi = defaultDraftApi,
    private readonly debounceMs = 250,
    private readonly onScopeChanged: (scope: DraftScope) => void = () => undefined,
  ) {
    this.cleanup = new DraftSessionCleanup({
      state: () => ({ operation: this.operation, edits: this.edits, scope: this.scope,
        scopeToken: this.view.scopeToken, policy: this.view.policy, prompt: this.view.prompt, persistedPrompt: this.persistedPrompt }),
      flush: () => this.flush(), enqueue: action => this.enqueue(action),
      load: scope => this.api.load(scope.projectId, scope.workspaceId),
      clear: (scope, submitted) => this.api.clear(scope.projectId, scope.workspaceId, {
        scopeToken: submitted.scopeToken, expectedRevision: submitted.revision,
      }),
      current: (operation, scope) => this.isCurrent(operation, scope),
      invalidate: (operation, scope) => { this.invalidate(operation, scope) },
      install: (scope, draft, operation) => this.install(scope, draft, operation),
      fail: error => this.fail(error),
    })
  }

  begin(scope: DraftScope): void {
    this.operation += 1
    this.cancelTimer()
    this.scope = scope
    this.edits = 0
    this.persistedPrompt = null
    this.drain = null
    Object.assign(this.view, emptyDraftSessionView())
  }

  async open(policy: ManagedTaskDraftPolicy): Promise<void> {
    const operation = ++this.operation
    const scope = this.scope
    const edits = this.edits
    const previousToken = this.view.scopeToken
    const previousPrompt = this.view.prompt
    const previousPersisted = this.persistedPrompt
    const previousRevision = this.view.revision
    const previousPolicy = this.view.policy
    this.cancelTimer()
    this.drain = null
    this.view.policy = policy
    this.view.error = null
    if (policy === 'memory_only') {
      this.persistedPrompt = null
      this.view.scopeToken = null
      this.view.revision = null
      this.view.status = 'memory'
      if (previousPolicy !== 'memory_only') this.view.prompt = ''
      return
    }
    if (policy === 'unavailable' || scope === null) {
      this.view.scopeToken = null
      this.view.revision = null
      this.view.status = 'unavailable'
      this.view.error = 'unavailable'
      this.view.prompt = ''
      return
    }
    this.view.scopeToken = null
    this.view.revision = null
    this.view.prompt = ''
    this.persistedPrompt = null
    this.view.status = 'loading'
    try {
      await this.queue
      if (!this.isCurrent(operation, scope)) return
      const loaded = await this.api.load(scope.projectId, scope.workspaceId)
      if (!this.isCurrent(operation, scope)) return
      if (loaded.scopeToken !== previousToken) { this.edits += 1; this.adopt(loaded); return }
      const localPrompt = this.edits === edits ? previousPrompt : this.view.prompt
      const localDirty = this.edits !== edits || previousPrompt !== (previousPersisted ?? '')
      const remoteChanged = loaded.revision !== previousRevision || loaded.prompt !== previousPersisted
      this.adopt(loaded, localDirty ? localPrompt : undefined)
      if (localDirty && remoteChanged) { this.cancelTimer(); this.view.status = 'conflict' }
    } catch (error) {
      if (!this.isCurrent(operation, scope)) return
      if (isDraftScopeChanged(error)) return this.invalidate(operation, scope, true)
      this.fail(error)
    }
  }
  edit(prompt: string): void {
    this.view.prompt = prompt
    this.edits += 1
    this.view.error = null
    if (this.view.policy === 'memory_only') {
      this.view.status = 'memory'
      return
    }
    if (this.view.policy !== 'protected_restart' || this.view.scopeToken === null) return
    this.view.status = prompt === (this.persistedPrompt ?? '') ? 'saved' : 'unsaved'
    this.schedule()
  }
  async flush(): Promise<SubmittedDraft | null> {
    if (this.view.policy === 'memory_only') return null
    if (this.view.policy !== 'protected_restart' || this.view.scopeToken === null || this.scope === null) {
      throw new ManagedTaskDraftError('unavailable')
    }
    this.cancelTimer()
    const draining = this.drain ?? this.flushWrites()
    this.drain = draining
    try { await draining }
    finally { if (this.drain === draining) this.drain = null }
    const scopeToken = this.view.scopeToken
    const revision = this.view.revision
    if (scopeToken === null || revision === null) throw new ManagedTaskDraftError('unavailable')
    await this.verifyCurrentDraft(scopeToken, revision)
    return { scopeToken, revision: this.view.revision ?? revision }
  }
  private async verifyCurrentDraft(token: string, revision: number): Promise<void> {
    return verifyDraftForSubmission({
      state: () => ({ operation: this.operation, edits: this.edits, scope: this.scope, persistedPrompt: this.persistedPrompt }),
      load: scope => this.api.load(scope.projectId, scope.workspaceId),
      current: (operation, scope) => this.isCurrent(operation, scope), edits: () => this.edits,
      invalidate: (operation, scope) => this.invalidate(operation, scope, true),
      setConflict: () => { this.view.status = 'conflict' }, fail: error => this.fail(error),
    }, token, revision)
  }
  private async flushWrites(): Promise<void> {
    const operation = this.operation
    const scope = this.scope
    if (scope === null) throw new ManagedTaskDraftError('unavailable')
    await this.queue
    if (!this.isCurrent(operation, scope)) throw new ManagedTaskDraftError('unavailable')
    this.throwIfBlocked()
    while (this.view.prompt !== (this.persistedPrompt ?? '')) {
      const token = this.view.scopeToken
      if (token === null) throw new ManagedTaskDraftError('unavailable')
      const prompt = this.view.prompt
      if (new TextEncoder().encode(prompt).byteLength > maxManagedTaskDraftBytes) {
        throw new ManagedTaskDraftError('unavailable')
      }
      this.view.status = 'saving'
      const write = this.enqueue(() => this.commit(scope, token, prompt, operation))
      await write
      if (!this.isCurrent(operation, scope)) throw new ManagedTaskDraftError('unavailable')
    }
    this.throwIfBlocked()
  }
  private throwIfBlocked(): void {
    if (this.view.status === 'conflict') throw new ManagedTaskDraftError('conflict')
    if (this.view.status === 'error' || this.view.status === 'unavailable') {
      throw new ManagedTaskDraftError(this.view.error ?? 'unavailable')
    }
  }
  async retry(): Promise<void> {
    if (this.view.status === 'conflict') return
    this.view.status = 'unsaved'
    await this.flush()
  }
  async reconcileConflict(choice: 'keep_local' | 'use_saved'): Promise<void> {
    return reconcileDraftConflict({
      state: () => ({ operation: this.operation, edits: this.edits, scope: this.scope,
        scopeToken: this.view.scopeToken, status: this.view.status, prompt: this.view.prompt }),
      load: scope => this.api.load(scope.projectId, scope.workspaceId),
      current: (operation, scope) => this.isCurrent(operation, scope),
      invalidate: (operation, scope) => { this.invalidate(operation, scope, true) },
      adopt: (draft, prompt) => this.adopt(draft, prompt),
      flush: () => this.flush(), fail: error => this.fail(error),
    }, choice)
  }

  async clearSubmitted(scope: DraftScope, submitted: SubmittedDraft): Promise<'cleared' | 'newer' | 'blocked'> {
    return this.cleanup.clearSubmitted(scope, submitted)
  }

  async release(): Promise<void> {
    if (this.view.status === 'saved') return
    try { await this.flush() } catch { /* The visible save state already records the failure. */ }
  }

  suspend(): void {
    this.operation += 1
    this.cancelTimer()
    this.drain = null
    this.persistedPrompt = null
    Object.assign(this.view, emptyDraftSessionView())
  }

  private invalidate(operation: number, scope: DraftScope, revalidate = false): void {
    if (!this.isCurrent(operation, scope)) return
    this.suspend()
    if (revalidate) this.onScopeChanged(scope)
  }

  clearMemory(): void {
    if (this.view.policy !== 'memory_only') return
    this.view.prompt = ''
    this.view.status = 'memory'
    this.edits += 1
  }

  private async commit(scope: DraftScope, token: string, prompt: string, operation: number): Promise<void> {
    return commitDraftWrite({
      current: (operation, scope) => this.isCurrent(operation, scope),
      token: () => this.view.scopeToken, revision: () => this.view.revision,
      save: (scope, write) => this.api.save(scope.projectId, scope.workspaceId, write),
      clear: (scope, token, revision) => this.api.clear(scope.projectId, scope.workspaceId, { scopeToken: token, expectedRevision: revision }),
      invalidate: (operation, scope) => this.invalidate(operation, scope, true),
      acknowledge: result => {
        this.view.revision = result.revision
        this.persistedPrompt = result.prompt
        this.view.status = this.view.prompt === (this.persistedPrompt ?? '') ? 'saved' : 'unsaved'
        this.view.error = null
      },
      fail: error => this.fail(error),
    }, scope, token, prompt, operation)
  }

  private enqueue(action: () => Promise<void>): Promise<void> {
    const next = this.queue.then(action)
    this.queue = next.then(() => undefined, () => undefined)
    return next
  }

  private schedule(): void {
    this.cancelTimer()
    if (this.view.status === 'unsaved' && new TextEncoder().encode(this.view.prompt).byteLength <= maxManagedTaskDraftBytes) {
      this.timer = setTimeout(() => { void this.flush().catch(() => undefined) }, this.debounceMs)
    }
  }

  private cancelTimer(): void {
    if (this.timer !== null) clearTimeout(this.timer)
    this.timer = null
  }

  private adopt(draft: ManagedTaskDraft, prompt = draft.prompt ?? ''): void {
    this.view.policy = 'protected_restart'
    this.view.prompt = prompt
    this.view.revision = draft.revision
    this.view.scopeToken = draft.scopeToken
    this.persistedPrompt = draft.prompt
    this.view.status = prompt === (draft.prompt ?? '') ? 'saved' : 'unsaved'
    this.view.error = null
    if (this.view.status === 'unsaved') this.schedule()
  }

  private install(scope: DraftScope, draft: ManagedTaskDraft, operation: number): boolean {
    if (!this.isCurrent(operation, scope)) return false
    if (this.scope === null) this.scope = scope
    if (this.scope.projectId !== scope.projectId || this.scope.workspaceId !== scope.workspaceId) return false
    if (this.view.scopeToken !== null && this.view.scopeToken !== draft.scopeToken) return false
    this.view.policy = 'protected_restart'
    this.view.scopeToken = draft.scopeToken
    this.view.revision = draft.revision
    this.persistedPrompt = draft.prompt
    if (this.view.status !== 'unsaved' && this.view.status !== 'saving') this.view.prompt = draft.prompt ?? ''
    this.view.status = this.view.prompt === (draft.prompt ?? '') ? 'saved' : 'unsaved'
    this.view.error = null
    return true
  }

  private fail(error: unknown): void {
    const code = error instanceof ManagedTaskDraftError ? error.code : 'unavailable'
    this.view.error = code === 'capacity' ? 'capacity' : 'unavailable'
    this.view.status = code === 'conflict' ? 'conflict' : 'error'
  }

  private isCurrent(operation: number, scope: DraftScope): boolean {
    return this.operation === operation && this.scope !== null
      && this.scope.projectId === scope.projectId && this.scope.workspaceId === scope.workspaceId
  }
}
