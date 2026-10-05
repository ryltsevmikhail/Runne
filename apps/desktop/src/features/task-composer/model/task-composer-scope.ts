import type { Ref } from 'vue'
import { prepareManagedTaskRun } from '@/entities/task-run/api/managed-task-run'
import type { ManagedTaskRunPreflight } from '@/entities/task-run/api/managed-task-run'
import type { DraftSession } from './draft-session'
import { loadPendingRun } from './pending-run'
import type { PendingRunBinding } from './pending-run'

export type ComposerStatus = 'waiting' | 'preparing' | 'ready' | 'unavailable' | 'starting' | 'uncertain' | 'accepted'
interface ScopeProps {
  readonly projectId: string
  readonly workspaceId: string
  readonly disabled: boolean
  readonly prepare?: typeof prepareManagedTaskRun | undefined
}
interface ScopeHost {
  readonly props: ScopeProps
  readonly draft: DraftSession
  readonly scopeOperation: Ref<number>
  readonly preflight: Ref<ManagedTaskRunPreflight | null>
  readonly status: Ref<ComposerStatus>
  readonly recoveryMessage: Ref<'not_committed' | 'uncertain' | 'unavailable' | 'newer_draft' | null>
  readonly recoveryStorageUnavailable: Ref<boolean>
  readonly operationFailed: Ref<boolean>
  readonly pending: Ref<PendingRunBinding | null>
  readonly localSubmissionToken: Ref<string | null>
  readonly draftCleanupReady: Ref<boolean>
  readonly draftVisible: Ref<boolean>
  readonly busy: Ref<boolean>
  current(operation: number, projectId: string, workspaceId: string): boolean
  storage(): Storage
  reconcile(operation: number, projectId: string, workspaceId: string, binding: PendingRunBinding): Promise<void>
  completeAccepted(operation: number, projectId: string, workspaceId: string, binding: PendingRunBinding, taskRunId: string): Promise<void>
}

export function useTaskComposerScope(host: ScopeHost) {
  const { props } = host

  function resetScopePresentation(): void {
    host.draftVisible.value = false
    host.preflight.value = null
    host.pending.value = null
    host.recoveryMessage.value = null
    host.recoveryStorageUnavailable.value = false
    host.operationFailed.value = false
    host.draftCleanupReady.value = false
    host.status.value = props.disabled ? 'waiting' : 'preparing'
    host.busy.value = true
  }

  async function activateScope(): Promise<void> {
    const operation = ++host.scopeOperation.value
    const projectId = props.projectId
    const workspaceId = props.workspaceId
    resetScopePresentation()
    host.localSubmissionToken.value = null
    await host.draft.release()
    if (operation !== host.scopeOperation.value || props.projectId !== projectId || props.workspaceId !== workspaceId) return
    host.draft.begin({ projectId, workspaceId })
    host.busy.value = false
    await loadScope(operation, projectId, workspaceId)
  }

  async function refreshScope(): Promise<void> {
    const prior = host.preflight.value
    const keepMemoryDraft = !props.disabled && host.draftVisible.value
      && host.draft.view.policy === 'memory_only'
      && prior?.projectId === props.projectId && prior.workspaceId === props.workspaceId
      ? prior.recoveryToken : null
    const operation = ++host.scopeOperation.value
    resetScopePresentation()
    await loadScope(operation, props.projectId, props.workspaceId, keepMemoryDraft)
  }

  async function loadScope(
    operation: number,
    projectId: string,
    workspaceId: string,
    keepMemoryDraft: string | null = null,
  ): Promise<void> {
    host.busy.value = false
    if (props.disabled) { host.draft.suspend(); host.status.value = 'waiting'; return }
    if (!projectId || !workspaceId) { host.status.value = 'unavailable'; return }
    let saved
    try { saved = loadPendingRun(workspaceId, host.storage()) }
    catch { host.recoveryStorageUnavailable.value = true; host.status.value = 'uncertain'; return }
    if (saved.status === 'corrupt') { host.status.value = 'uncertain'; host.recoveryMessage.value = 'unavailable'; return }
    if (saved.status === 'pending') {
      if (saved.binding.projectId !== projectId) { host.status.value = 'uncertain'; host.recoveryMessage.value = 'unavailable'; return }
      host.pending.value = saved.binding
      if (saved.binding.acceptedTaskRunId !== undefined) {
        await host.completeAccepted(operation, projectId, workspaceId, saved.binding, saved.binding.acceptedTaskRunId)
        if (keepMemoryDraft !== null && host.current(operation, projectId, workspaceId)
            && saved.binding.recoveryToken === keepMemoryDraft
            && host.draft.view.policy === 'memory_only') host.draftVisible.value = true
      } else {
        host.status.value = 'uncertain'
        await host.reconcile(operation, projectId, workspaceId, saved.binding)
      }
      return
    }
    host.status.value = 'preparing'
    try {
      const next = await (props.prepare ?? prepareManagedTaskRun)(projectId, workspaceId)
      if (!host.current(operation, projectId, workspaceId)) return
      if (next.projectId !== projectId || next.workspaceId !== workspaceId) throw new Error('Scope mismatch')
      host.preflight.value = next
      host.status.value = next.status === 'ready' && next.canStart && next.generation !== null
        && next.conversationId !== null && next.recoveryToken !== null ? 'ready' : 'unavailable'
      await host.draft.open(next.draftPolicy)
      if (host.current(operation, projectId, workspaceId)) host.draftVisible.value = true
    } catch {
      if (!host.current(operation, projectId, workspaceId)) return
      host.status.value = 'unavailable'
      if (host.draft.view.policy === 'unknown') await host.draft.open('unavailable')
      host.draftVisible.value = false
    }
  }

  return { activateScope, refreshScope }
}
