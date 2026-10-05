import { ManagedTaskDraftError } from '@/entities/task-run/api/managed-task-draft'
import {
  clearManagedTaskDraft, loadManagedTaskDraft, saveManagedTaskDraft,
} from '@/entities/task-run/api/managed-task-draft'
import type { ManagedTaskDraftPolicy } from '@/entities/task-run/api/managed-task-draft'

export type DraftSaveStatus = 'loading' | 'memory' | 'saved' | 'unsaved' | 'saving' | 'error' | 'conflict' | 'unavailable'
export interface DraftSessionView {
  policy: ManagedTaskDraftPolicy | 'unknown'
  status: DraftSaveStatus
  prompt: string
  revision: number | null
  scopeToken: string | null
  error: 'capacity' | 'unavailable' | null
}
export interface DraftScope { readonly projectId: string, readonly workspaceId: string }
export interface DraftApi {
  readonly load: typeof loadManagedTaskDraft
  readonly save: typeof saveManagedTaskDraft
  readonly clear: typeof clearManagedTaskDraft
}
export interface SubmittedDraft { readonly scopeToken: string, readonly revision: number }

export const defaultDraftApi: DraftApi = {
  load: loadManagedTaskDraft, save: saveManagedTaskDraft, clear: clearManagedTaskDraft,
}
export function isDraftScopeChanged(error: unknown): boolean {
  return error instanceof ManagedTaskDraftError && error.code === 'scope_changed'
}
export const emptyDraftSessionView = (): DraftSessionView => ({
  policy: 'unknown', status: 'loading', prompt: '', revision: null, scopeToken: null, error: null,
})
