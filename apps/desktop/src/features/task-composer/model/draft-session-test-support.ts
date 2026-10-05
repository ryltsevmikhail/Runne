import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraft, ManagedTaskDraftClear, ManagedTaskDraftWrite } from '@/entities/task-run/api/managed-task-draft'
import type { DraftApi } from './draft-session'
import { DraftSession } from './draft-session'

export const projectId = '018f2e3a-7000-7000-8000-000000000213'
export const workspaceId = '018f2e3a-7000-7000-8000-000000000212'
export const token = 'a'.repeat(64)
export const otherToken = 'b'.repeat(64)
type SaveCall = { readonly write: ManagedTaskDraftWrite, readonly finish: (draft: ManagedTaskDraft) => void, readonly reject: (error: Error) => void }

export class DraftStore {
  current: ManagedTaskDraft = { revision: 0, prompt: null, scopeToken: token }
  saves: SaveCall[] = []
  clears: ManagedTaskDraftClear[] = []
  writeCalls = 0
  holdSaves = false
  failClear = false
  loadResult: Promise<ManagedTaskDraft> | null = null
  readonly api: DraftApi = {
    load: async () => this.loadResult ?? this.current,
    save: async (_project, _workspace, write) => { this.writeCalls += 1; return this.save(write) },
    clear: async (_project, _workspace, clear) => this.clear(clear),
  }

  private save(write: ManagedTaskDraftWrite): Promise<ManagedTaskDraft> {
    if (write.scopeToken !== this.current.scopeToken || write.expectedRevision !== this.current.revision) {
      return Promise.reject(new ManagedTaskDraftError('conflict'))
    }
    if (!this.holdSaves) {
      this.current = { revision: this.current.revision + 1, prompt: write.prompt, scopeToken: this.current.scopeToken }
      return Promise.resolve(this.current)
    }
    return new Promise((resolve, reject) => this.saves.push({
      write,
      finish: draft => { this.current = draft; resolve(draft) },
      reject,
    }))
  }

  private clear(clear: ManagedTaskDraftClear): Promise<ManagedTaskDraft> {
    this.clears.push(clear)
    if (this.failClear) return Promise.reject(new ManagedTaskDraftError('unavailable'))
    if (clear.scopeToken !== this.current.scopeToken) return Promise.reject(new ManagedTaskDraftError('conflict'))
    if (this.current.prompt === null && this.current.revision > clear.expectedRevision) return Promise.resolve(this.current)
    if (clear.expectedRevision !== this.current.revision) return Promise.reject(new ManagedTaskDraftError('conflict'))
    this.current = { revision: this.current.revision + 1, prompt: null, scopeToken: this.current.scopeToken }
    return Promise.resolve(this.current)
  }
}

export function session(store: DraftStore, id = workspaceId): DraftSession {
  const draft = new DraftSession(store.api, 60_000)
  draft.begin({ projectId, workspaceId: id })
  return draft
}
